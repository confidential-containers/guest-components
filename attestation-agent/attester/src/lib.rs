// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate strum;

use anyhow::*;

pub mod sample;

#[cfg(feature = "az-snp-vtpm-attester")]
pub mod az_snp_vtpm;

#[cfg(feature = "tdx-attester")]
pub mod tdx;

#[cfg(feature = "sgx-attester")]
pub mod sgx_dcap;

#[cfg(feature = "snp-attester")]
pub mod snp;

/// The supported TEE types:
/// - Tdx: TDX TEE.
/// - Sgx: SGX TEE with a LibOS.
/// - AzSnpVtpm: SEV-SNP TEE for Azure CVMs.
/// - Snp: SEV-SNP TEE.
/// - Sample: A dummy TEE that used to test/demo the KBC functionalities.
#[derive(Debug, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum Tee {
    Tdx,
    #[strum(serialize = "sgx")]
    Sgx,
    AzSnpVtpm,
    Snp,
    Sample,
    Unknown,
}

impl Tee {
    pub fn to_attester(&self) -> Result<Box<dyn Attester + Send + Sync>> {
        match self {
            Tee::Sample => Ok(Box::<sample::SampleAttester>::default()),
            #[cfg(feature = "tdx-attester")]
            Tee::Tdx => Ok(Box::<tdx::TdxAttester>::default()),
            #[cfg(feature = "sgx-attester")]
            Tee::Sgx => Ok(Box::<sgx_dcap::SgxDcapAttester>::default()),
            #[cfg(feature = "az-snp-vtpm-attester")]
            Tee::AzSnpVtpm => Ok(Box::<az_snp_vtpm::AzSnpVtpmAttester>::default()),
            #[cfg(feature = "snp-attester")]
            Tee::Snp => Ok(Box::<snp::SnpAttester>::default()),
            _ => bail!("TEE is not supported!"),
        }
    }
}

pub trait Attester {
    fn get_evidence(&self, report_data: String) -> Result<String>;
}

// Detect which TEE platform the KBC running environment is.
pub fn detect_tee_type() -> Tee {
    if sample::detect_platform() {
        return Tee::Sample;
    }

    #[cfg(feature = "tdx-attester")]
    if tdx::detect_platform() {
        return Tee::Tdx;
    }

    #[cfg(feature = "sgx-attester")]
    if sgx_dcap::detect_platform() {
        return Tee::Sgx;
    }

    #[cfg(feature = "az-snp-vtpm-attester")]
    if az_snp_vtpm::detect_platform() {
        return Tee::AzSnpVtpm;
    }

    #[cfg(feature = "snp-attester")]
    if snp::detect_platform() {
        return Tee::Snp;
    }
    Tee::Unknown
}
