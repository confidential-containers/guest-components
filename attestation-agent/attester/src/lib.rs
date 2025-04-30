// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_types::{Tee, TeePubKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use crypto::HashAlgorithm;

pub mod sample;
pub mod sample_device;
pub mod utils;

#[cfg(feature = "az-snp-vtpm-attester")]
pub mod az_snp_vtpm;

#[cfg(feature = "az-tdx-vtpm-attester")]
pub mod az_tdx_vtpm;

#[cfg(feature = "cca-attester")]
pub mod cca;

#[cfg(feature = "tdx-attester")]
pub mod tdx;

#[cfg(feature = "sgx-attester")]
pub mod sgx_dcap;

#[cfg(feature = "snp-attester")]
pub mod snp;

#[cfg(feature = "csv-attester")]
pub mod csv;

#[cfg(feature = "tsm-report")]
pub mod tsm_report;

#[cfg(feature = "se-attester")]
pub mod se;

pub(crate) type BoxedAttester = Box<dyn Attester + Send + Sync>;

impl TryFrom<Tee> for BoxedAttester {
    type Error = anyhow::Error;

    fn try_from(value: Tee) -> Result<Self> {
        let attester: Box<dyn Attester + Send + Sync> = match value {
            Tee::Sample => Box::<sample::SampleAttester>::default(),
            Tee::SampleDevice => Box::<sample_device::SampleDeviceAttester>::default(),
            #[cfg(feature = "tdx-attester")]
            Tee::Tdx => Box::<tdx::TdxAttester>::default(),
            #[cfg(feature = "sgx-attester")]
            Tee::Sgx => Box::<sgx_dcap::SgxDcapAttester>::default(),
            #[cfg(feature = "az-snp-vtpm-attester")]
            Tee::AzSnpVtpm => Box::<az_snp_vtpm::AzSnpVtpmAttester>::default(),
            #[cfg(feature = "az-tdx-vtpm-attester")]
            Tee::AzTdxVtpm => Box::<az_tdx_vtpm::AzTdxVtpmAttester>::default(),
            #[cfg(feature = "cca-attester")]
            Tee::Cca => Box::<cca::CcaAttester>::default(),
            #[cfg(feature = "snp-attester")]
            Tee::Snp => Box::<snp::SnpAttester>::default(),
            #[cfg(feature = "csv-attester")]
            Tee::Csv => Box::<csv::CsvAttester>::default(),
            #[cfg(feature = "se-attester")]
            Tee::Se => Box::<se::SeAttester>::default(),
            _ => bail!("TEE is not supported!"),
        };

        Ok(attester)
    }
}

pub enum InitDataResult {
    Ok,
    Unsupported,
}

pub(crate) type TeeEvidence = serde_json::Value;

#[async_trait::async_trait]
pub(crate) trait Attester {
    /// Call the hardware driver to get the Hardware specific evidence.
    /// The parameter `report_data` will be used as the user input of the
    /// evidence to avoid reply attack.
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence>;

    /// Extend TEE specific dynamic measurement register
    /// to enable dynamic measurement capabilities for input data at runtime.
    async fn extend_runtime_measurement(
        &self,
        _event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        bail!("Unimplemented")
    }

    async fn bind_init_data(&self, _init_data_digest: &[u8]) -> Result<InitDataResult> {
        Ok(InitDataResult::Unsupported)
    }

    /// This function is used to get the runtime measurement registry value of
    /// the given PCR register index. Different platforms have different mapping
    /// relationship between PCR and platform RTMR.
    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        bail!("Unimplemented")
    }
}

// Detect which TEE platform the KBC running environment is.
pub fn detect_tee_type() -> Tee {
    #[cfg(feature = "tdx-attester")]
    if tdx::detect_platform() {
        return Tee::Tdx;
    }

    #[cfg(feature = "sgx-attester")]
    if sgx_dcap::detect_platform() {
        return Tee::Sgx;
    }

    #[cfg(feature = "az-tdx-vtpm-attester")]
    if az_tdx_vtpm::detect_platform() {
        return Tee::AzTdxVtpm;
    }

    #[cfg(feature = "az-snp-vtpm-attester")]
    if az_snp_vtpm::detect_platform() {
        return Tee::AzSnpVtpm;
    }

    #[cfg(feature = "snp-attester")]
    if snp::detect_platform() {
        return Tee::Snp;
    }

    #[cfg(feature = "csv-attester")]
    if csv::detect_platform() {
        return Tee::Csv;
    }

    #[cfg(feature = "cca-attester")]
    if cca::detect_platform() {
        return Tee::Cca;
    }

    #[cfg(feature = "se-attester")]
    if se::detect_platform() {
        return Tee::Se;
    }

    log::warn!(
        "No TEE platform detected. Sample Attester will be used.
         If you are expecting to collect evidence from inside a confidential guest,
         either your guest is not configured correctly, or your attestation client
         was not built with support for the platform.

         Verify that your guest is a confidential guest and that your client
         (such as kbs-client or attestation-agent) was built with the feature
         corresponding to your platform.

         Attestation will continue using the fallback sample attester."
    );
    Tee::Sample
}

/// Get any additional TEEs that might be connected to the guest,
/// such as a confidential device.
pub fn detect_attestable_devices() -> Vec<Tee> {
    let mut additional_devices = vec![];

    if sample_device::detect_platform() {
        additional_devices.push(Tee::SampleDevice);
    }

    additional_devices
}

/// The CompositeAttester struct is an interface to all the attesters
/// that represent a confidential guest.
pub struct CompositeAttester {
    primary_attester_type: Tee,
    primary_attester: BoxedAttester,
    additional_attesters: HashMap<Tee, BoxedAttester>,
}

/// CompositeEvidence is the combined evidence from all the TEEs
/// that represent the guest.
#[derive(Serialize, Deserialize)]
pub struct CompositeEvidence {
    primary_evidence: TeeEvidence,
    // The additional evidence is a map of Tee -> evidence,
    // but we convert it to a string to avoid any inconsistencies
    // with serialization. The string in this struct is exactly
    // what is used to calculate the runtime data.
    additional_evidence: String,
}

impl CompositeAttester {
    pub fn new() -> Result<Self> {
        let primary_tee = detect_tee_type();
        let additional_tees = detect_attestable_devices();

        let mut additional_attesters = HashMap::new();
        for tee in additional_tees {
            additional_attesters.insert(tee, tee.try_into()?);
        }

        Ok(Self {
            primary_attester_type: primary_tee,
            primary_attester: primary_tee.try_into()?,
            additional_attesters,
        })
    }

    pub fn tee_type(&self) -> Tee {
        self.primary_attester_type
    }

    /// Get evidence for the guest.
    /// If the guest has devices/TEEs beyond the CPU,
    /// composite evidence will be generated.
    /// The evidence from the additional devices will be collected first
    /// so that it can be bound to the evidence of the primary device
    /// via the report/runtime data.
    pub async fn evidence(
        &self,
        tee_pubkey: TeePubKey,
        nonce: String,
        hash_algorithm: HashAlgorithm,
    ) -> Result<String> {
        let additional_evidence = match self.additional_attesters.is_empty() {
            true => "".to_string(),
            false => {
                // Calculate the runtime data for devices, which does not include the
                // device evidence.
                let device_runtime_data = json!({
                    "tee-pubkey": tee_pubkey,
                    "nonce": nonce,
                });

                let device_runtime_data = serde_json::to_string(&device_runtime_data)
                    .context("serialize runtime data failed")?;
                let device_runtime_data = hash_algorithm.digest(device_runtime_data.as_bytes());

                let additional_evidence = self.additional_evidence(device_runtime_data).await?;
                serde_json::to_string(&additional_evidence)?
            }
        };

        // Calculate the runtime data for the primary attester, which includes
        // the device evidence retrieved above.
        let primary_runtime_data = match self.primary_attester_type {
            // SE handles the report data differently. As such, it does not support
            // multi-device attestation.
            Tee::Se => {
                if !self.additional_attesters.is_empty() {
                    bail!("Cannot attest multiple devices on s390x platform.")
                }
                nonce.into_bytes()
            }
            _ => {
                let primary_runtime_data = json!({
                    "tee-pubkey": tee_pubkey,
                    "nonce": nonce,
                    "additional-evidence": additional_evidence,
                });
                let primary_runtime_data = serde_json::to_string(&primary_runtime_data)
                    .context("serialize runtime data failed")?;
                hash_algorithm.digest(primary_runtime_data.as_bytes())
            }
        };
        let primary_evidence = self.primary_evidence(primary_runtime_data).await?;

        let guest_evidence = CompositeEvidence {
            primary_evidence,
            additional_evidence,
        };
        Ok(serde_json::to_string(&guest_evidence)?)
    }

    /// Get the evidence from the primary attester.
    /// The caller is responsible for handling the report data.
    pub async fn primary_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        self.primary_attester.get_evidence(report_data).await
    }

    /// Get the evidence from any additional attesters.
    /// The caller is responsible for handling the report data.
    pub async fn additional_evidence(
        &self,
        report_data: Vec<u8>,
    ) -> Result<HashMap<Tee, TeeEvidence>> {
        let mut evidence = HashMap::new();

        for (tee, attester) in &self.additional_attesters {
            evidence.insert(*tee, attester.get_evidence(report_data.clone()).await?);
        }

        Ok(evidence)
    }

    /// Extend TEE specific dynamic measurement register
    /// to enable dynamic measurement capabilities for input data at runtime.
    /// This will be carried out via the primary attester only.
    pub async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        self.primary_attester
            .extend_runtime_measurement(event_digest, register_index)
            .await
    }

    /// Bind init data to the hardware evidence of the primary attester
    /// either by checking that it matches an existing field or by extending
    /// a PCR.
    pub async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        self.primary_attester.bind_init_data(init_data_digest).await
    }

    /// Get the current PCR value for some index.
    /// This will be fulfilled via the primary attester.
    /// It will raise an error if the primary attester
    /// does not support runtime measurement.
    pub async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        self.primary_attester
            .get_runtime_measurement(pcr_index)
            .await
    }
}
