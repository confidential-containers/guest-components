// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use ioctl_sys::ioctl;
use raw_cpuid::{CpuId, Hypervisor};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Error;
use std::os::unix::io::AsRawFd;

use crate::Attester;

// Length of the REPORTDATA used in TDG.MR.REPORT TDCALL
const TDX_REPORTDATA_LEN: usize = 64;

// Length of TDREPORT used in TDG.MR.REPORT TDCALL
const TDX_REPORT_LEN: usize = 1024;

#[repr(C)]
#[derive(Debug)]
pub struct TdxReportReq {
    reportdata: [u8; TDX_REPORTDATA_LEN],
    tdreport: [u8; TDX_REPORT_LEN],
}

impl TdxReportReq {
    pub fn new(reportdata: [u8; TDX_REPORTDATA_LEN]) -> Self {
        Self {
            reportdata,
            tdreport: [0; TDX_REPORT_LEN],
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AzTdQuoteRequest {
    report: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct AzTdQuoteResponse {
    quote: String,
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            reportdata: [0; TDX_REPORTDATA_LEN],
            tdreport: [0; TDX_REPORT_LEN],
        }
    }
}

ioctl!(readwrite tdx_cmd_get_report0 with b'T', 0x01; TdxReportReq);

pub(super) async fn get_hyperv_tdx_evidence(report_data: &[u8]) -> Result<String> {
    let file = OpenOptions::new().write(true).open("/dev/tdx_guest")?;
    let fd = file.as_raw_fd();
    let mut tdx_req = TdxReportReq::new(report_data.try_into()?);
    unsafe {
        let err = tdx_cmd_get_report0(fd, &mut tdx_req);
        if err != 0 {
            bail!("TDX Attester: ioctl failed: {}", Error::last_os_error());
        }
    }
    let report = base64::encode_config(tdx_req.tdreport, base64::URL_SAFE_NO_PAD);
    let tdquotereq = AzTdQuoteRequest { report };
    let req = reqwest::Client::new()
        .post("http://169.254.169.254/acc/tdquote")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .body(serde_json::to_string(&tdquotereq)?)
        .send()
        .await?;
    let tdquoteresp = req.json::<AzTdQuoteResponse>().await?;
    let quote = base64::decode_config(tdquoteresp.quote, base64::URL_SAFE_NO_PAD)?;
    let evidence = super::TdxEvidence {
        cc_eventlog: None,
        quote: base64::encode(quote),
    };
    serde_json::to_string(&evidence).context("TDX Attester: Failed to serialize evidence")
}

pub(super) fn detect_platform() -> bool {
    // check cpuid if we are in a Hyper-V guest
    let cpuid = CpuId::new();
    if let Some(hypervisor) = cpuid.get_hypervisor_info() {
        hypervisor.identify() == Hypervisor::HyperV
    } else {
        false
    }
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, report_data: String) -> Result<String> {
        let report_data_bin = super::convert_report_data(report_data)?;
        get_hyperv_tdx_evidence(&report_data_bin).await
    }
}
