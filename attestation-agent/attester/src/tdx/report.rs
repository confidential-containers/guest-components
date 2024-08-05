// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use scroll::Pread;

#[repr(C)]
#[derive(Pread)]
/// Type header of TDREPORT_STRUCT.
pub struct TdTransportType {
    /// Type of the TDREPORT (0 - SGX, 81 - TDX, rest are reserved).
    pub type_: u8,

    /// Subtype of the TDREPORT (Default value is 0).
    pub sub_type: u8,

    /// TDREPORT version (Default value is 0).
    pub version: u8,

    /// Added for future extension.
    pub reserved: u8,
}

#[repr(C)]
#[derive(Pread)]
/// TDX guest report data, MAC and TEE hashes.
pub struct ReportMac {
    /// TDREPORT type header.
    pub type_: TdTransportType,

    /// Reserved for future extension.
    pub reserved1: [u8; 12],

    /// CPU security version.
    pub cpu_svn: [u8; 16],

    /// SHA384 hash of TEE TCB INFO.
    pub tee_tcb_info_hash: [u8; 48],

    /// SHA384 hash of TDINFO_STRUCT.
    pub tee_td_info_hash: [u8; 48],

    /// User defined unique data passed in TDG.MR.REPORT request.
    pub reportdata: [u8; 64],

    /// Reserved for future extension.
    pub reserved2: [u8; 32],

    /// CPU MAC ID.
    pub mac: [u8; 32],
}

#[repr(C)]
#[derive(Pread)]
/// TDX guest measurements and configuration.
pub struct TdInfo {
    /// TDX Guest attributes (like debug, spet_disable, etc).
    pub attr: [u8; 8],

    /// Extended features allowed mask.
    pub xfam: u64,

    /// Build time measurement register.
    pub mrtd: [u64; 6],

    /// Software-defined ID for non-owner-defined configuration of the guest - e.g., run-time or OS configuration.
    pub mrconfigid: [u8; 48],

    /// Software-defined ID for the guest owner.
    pub mrowner: [u64; 6],

    /// Software-defined ID for owner-defined configuration of the guest - e.g., specific to the workload.
    pub mrownerconfig: [u64; 6],

    /// Run time measurement registers.
    pub rtmr: [u64; 24],

    /// For future extension.
    pub reserved: [u64; 14],
}

#[repr(C)]
#[derive(Pread)]
/// Output of TDCALL[TDG.MR.REPORT].
pub struct TdReport {
    /// Mac protected header of size 256 bytes.
    pub report_mac: ReportMac,

    /// Additional attestable elements in the TCB are not reflected in the report_mac.
    pub tee_tcb_info: [u8; 239],

    /// Added for future extension.
    pub reserved: [u8; 17],

    /// Measurements and configuration data of size 512 bytes.
    pub tdinfo: TdInfo,
}
