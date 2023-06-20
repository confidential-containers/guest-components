// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use az_snp_vtpm::{imds, vtpm};
use log::debug;
use raw_cpuid::{cpuid, CpuId, Hypervisor};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub fn detect_platform() -> bool {
    if !Path::new("/dev/tpm0").exists() {
        debug!("vTPM device not found");
        return false;
    }

    let cpuid = CpuId::new();
    let Some(hyper_info) = cpuid.get_hypervisor_info() else {
        debug!("Not a VM");
        return false;
    };
    let hypervisor = hyper_info.identify();
    debug!("Hypervisor: {:?}", hypervisor);
    if hypervisor != Hypervisor::HyperV {
        return false;
    }

    const HYPERV_CPUID_FEATURES: u32 = 0x40000003;
    const HV_ISOLATION: u32 = 1 << 22;
    let hv_features = cpuid!(HYPERV_CPUID_FEATURES);
    if hv_features.ebx & HV_ISOLATION == 0 {
        debug!("VM is not an isolation VM");
        return false;
    }

    const HYPERV_CPUID_ISOLATION_CONFIG: u32 = 0x4000000C;
    const HV_ISOLATION_TYPE: u32 = 0xF;
    const HV_ISOLATION_TYPE_SNP: u32 = 2;
    let hv_isol_config = cpuid!(HYPERV_CPUID_ISOLATION_CONFIG);
    if hv_isol_config.ebx & HV_ISOLATION_TYPE != HV_ISOLATION_TYPE_SNP {
        debug!("VM is not an SNP VM");
        return false;
    }
    true
}

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
    vcek: String,
}

impl Attester for AzSnpVtpmAttester {
    fn get_evidence(&self, report_data: String) -> Result<String> {
        let report = vtpm::get_report()?;
        let report_data_bin = base64::decode(report_data)?;
        let quote = vtpm::get_quote(&report_data_bin)?;
        let certs = imds::get_certs()?;
        let vcek = certs.vcek;

        let evidence = Evidence {
            quote,
            report,
            vcek,
        };

        Ok(serde_json::to_string(&evidence)?)
    }
}
