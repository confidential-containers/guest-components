// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_types::Tee;

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

#[cfg(feature = "hygon-dcu-attester")]
pub mod hygon_dcu;

#[cfg(feature = "tsm-report")]
pub mod tsm_report;

#[cfg(feature = "se-attester")]
pub mod se;

#[cfg(feature = "tpm-attester")]
pub mod tpm;
pub mod tpm_utils;

pub type BoxedAttester = Box<dyn Attester + Send + Sync>;

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
            #[cfg(feature = "hygon-dcu-attester")]
            Tee::HygonDcu => Box::<hygon_dcu::DcuAttester>::default(),
            #[cfg(feature = "se-attester")]
            Tee::Se => Box::<se::SeAttester>::default(),
            #[cfg(feature = "tpm-attester")]
            Tee::Tpm => Box::new(tpm::TpmAttester::new()?),
            _ => bail!("TEE is not supported!"),
        };

        Ok(attester)
    }
}

pub enum InitDataResult {
    Ok,
    Unsupported,
}

pub type TeeEvidence = serde_json::Value;

#[async_trait::async_trait]
pub trait Attester {
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

    #[cfg(feature = "tpm-attester")]
    if tpm::detect_platform() {
        return Tee::Tpm;
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

    #[cfg(feature = "hygon-dcu-attester")]
    if hygon_dcu::detect_platform() {
        additional_devices.push(Tee::HygonDcu);
    }

    additional_devices
}
