// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_types::Tee;

pub mod sample;
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

pub type BoxedAttester = Box<dyn Attester + Send + Sync>;

impl TryFrom<Tee> for BoxedAttester {
    type Error = anyhow::Error;

    fn try_from(value: Tee) -> Result<Self> {
        let attester: Box<dyn Attester + Send + Sync> = match value {
            Tee::Sample => Box::<sample::SampleAttester>::default(),
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

#[async_trait::async_trait]
pub trait Attester {
    /// Each attester should define which category of devices it represents.
    /// This could be something like "cpu" or "gpu" or any other scheme
    /// used by the attester.
    /// Ultimately this class will represent a module in the attestation token
    /// signed by the attestation service.
    /// This class should be more generic than the Tee Type.
    /// There may be multiple attesters of the same type active in the same guest..
    fn device_class(&self) -> String {
        "cpu".to_string()
    }

    /// Call the hardware driver to get the Hardware specific evidence.
    /// The parameter `report_data` will be used as the user input of the
    /// evidence to avoid reply attack.
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String>;

    async fn bind_init_data(&self, _init_data_digest: &[u8]) -> Result<InitDataResult> {
        Ok(InitDataResult::Unsupported)
    }

    /// Attesters that support runtime measurement, and are able to implement
    /// the get_runtime_measurement and extend_runtime_measurement functions
    /// below, should return true.
    fn supports_runtime_measurement(&self) -> bool {
        false
    }

    /// This function is used to get the runtime measurement registry value of
    /// the given PCR register index. Different platforms have different mapping
    /// relationship between PCR and platform RTMR.
    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        bail!("Unimplemented")
    }

    /// Extend TEE specific dynamic measurement register
    /// to enable dynamic measurement capabilities for input data at runtime.
    async fn extend_runtime_measurement(
        &self,
        _event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        bail!("Unimplemented")
    }
}

/// Detect TEE platforms active in this environment.
/// One guest could support multiple platforms simultaneously,
/// such as a CPU TEE and confidential devices.
pub fn detect_tee_types() -> Vec<Tee> {
    let mut tee_types = vec![];
    #[cfg(feature = "tdx-attester")]
    if tdx::detect_platform() {
        tee_types.push(Tee::Tdx);
    }

    #[cfg(feature = "sgx-attester")]
    if sgx_dcap::detect_platform() {
        tee_types.push(Tee::Sgx);
    }

    #[cfg(feature = "az-tdx-vtpm-attester")]
    if az_tdx_vtpm::detect_platform() {
        tee_types.push(Tee::AzTdxVtpm);
    }

    #[cfg(feature = "az-snp-vtpm-attester")]
    if az_snp_vtpm::detect_platform() {
        tee_types.push(Tee::AzSnpVtpm);
    }

    #[cfg(feature = "snp-attester")]
    if snp::detect_platform() {
        tee_types.push(Tee::Snp);
    }

    #[cfg(feature = "csv-attester")]
    if csv::detect_platform() {
        tee_types.push(Tee::Csv);
    }

    #[cfg(feature = "cca-attester")]
    if cca::detect_platform() {
        tee_types.push(Tee::Cca);
    }

    #[cfg(feature = "se-attester")]
    if se::detect_platform() {
        tee_types.push(Tee::Se);
    }

    if tee_types.is_empty() {
        log::warn!("No TEE platform detected. Sample Attester will be used.");
        tee_types.push(Tee::Sample);
    }

    tee_types
}
