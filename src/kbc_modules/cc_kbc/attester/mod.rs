// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

pub mod sample;

/// The supported TEE types:
/// - Tdx: TDX TEE.
/// - Sgx: SGX TEE.
/// - Sevsnp: SEV-SNP TEE.
/// - Sample: A dummy TEE that used to test/demo the KBC functionalities.
#[derive(Debug, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum TEE {
    Tdx,
    Sgx,
    Sevsnp,
    Sample,
    Unknown,
}

impl TEE {
    pub fn to_attester(&self) -> Result<Box<dyn Attester + Send + Sync>> {
        match self {
            TEE::Sample => {
                Ok(Box::new(sample::SampleAttester::default()) as Box<dyn Attester + Send + Sync>)
            }
            _ => Err(anyhow!("TEE is not supported!")),
        }
    }
}

pub trait Attester {
    fn get_evidence(&self, report_data: String) -> Result<String>;
}

// Detect which TEE platform the KBC running environment is.
pub fn detect_tee_type() -> TEE {
    if sample::detect_platform() {
        TEE::Sample
    } else {
        TEE::Unknown
    }
}
