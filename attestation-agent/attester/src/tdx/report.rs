// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
/// Type header of TDREPORT_STRUCT.
pub(super) struct TdTransportType {
    /// Type of the TDREPORT (0 - SGX, 81 - TDX, rest are reserved).
    pub(super) type_: u8,

    /// Subtype of the TDREPORT (Default value is 0).
    pub(super) sub_type: u8,

    /// TDREPORT version (Default value is 0).
    pub(super) version: u8,

    /// Added for future extension.
    pub(super) reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
/// TDX guest report data, MAC and TEE hashes.
pub(super) struct ReportMac {
    /// TDREPORT type header.
    pub(super) type_: TdTransportType,

    /// Reserved for future extension.
    pub(super) reserved1: [u8; 12],

    /// CPU security version.
    pub(super) cpu_svn: [u8; 16],

    /// SHA384 hash of TEE TCB INFO.
    pub(super) tee_tcb_info_hash: [u8; 48],

    /// SHA384 hash of TDINFO_STRUCT.
    pub(super) tee_td_info_hash: [u8; 48],

    /// User defined unique data passed in TDG.MR.REPORT request.
    pub(super) reportdata: [u8; 64],

    /// Reserved for future extension.
    pub(super) reserved2: [u8; 32],

    /// CPU MAC ID.
    pub(super) mac: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
/// TDX guest measurements and configuration.
pub(super) struct TdInfo {
    /// TDX Guest attributes (like debug, spet_disable, etc).
    pub(super) attr: [u8; 8],

    /// Extended features allowed mask.
    pub(super) xfam: u64,

    /// Build time measurement register.
    pub(super) mrtd: [u64; 6],

    /// Software-defined ID for non-owner-defined configuration of the guest - e.g., run-time or OS configuration.
    pub(super) mrconfigid: [u8; 48],

    /// Software-defined ID for the guest owner.
    pub(super) mrowner: [u64; 6],

    /// Software-defined ID for owner-defined configuration of the guest - e.g., specific to the workload.
    pub(super) mrownerconfig: [u64; 6],

    /// Run time measurement registers.
    pub(super) rtmr: [u64; 24],

    /// For future extension.
    pub(super) reserved: [u64; 14],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
/// Output of TDCALL[TDG.MR.REPORT].
pub(super) struct TdReport {
    /// Mac protected header of size 256 bytes.
    pub(super) report_mac: ReportMac,

    /// Additional attestable elements in the TCB are not reflected in the report_mac.
    pub(super) tee_tcb_info: [u8; 239],

    /// Added for future extension.
    pub(super) reserved: [u8; 17],

    /// Measurements and configuration data of size 512 bytes.
    pub(super) tdinfo: TdInfo,
}

impl TdReport {
    pub(super) fn get_rtmr(&self, rtmr_index: usize) -> Vec<u8> {
        let mut rtmr_u8 = Vec::new();
        let rtmr = &self.tdinfo.rtmr[rtmr_index * 6..(rtmr_index + 1) * 6];
        for i in rtmr {
            rtmr_u8.extend_from_slice(&i.to_le_bytes());
        }

        rtmr_u8
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use crate::tdx::{TdxAttester, report::TdReport};

    /// This test uses a fixture of tdx-report to check if the get_runtime_measurement function works correctly.
    /// The following test PCRs are mapping to TDX RTMR 0, 1, 2 and 3
    #[rstest]
    #[case(
        1,
        "f4ec1a04670fe7926cd5de4aef9aaa7689ab4ceaa132d7c5242b47f67dfaaea64c372a17ad68fef9a6ac99aabbddabdc"
    )]
    #[case(
        2,
        "4e5f8826653198ab4bc5156fbe4bc99db054c0b8239a16c4b59249fb427f4acc50eed1b46a85c7d526c4e1e47621b14c"
    )]
    #[case(
        8,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    #[case(
        16,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    fn get_runtime_measurement(#[case] pcr_index: u64, #[case] expected: &str) {
        use zerocopy::FromBytes;

        use crate::Attester;

        let report_bin = include_bytes!("../../test/tdx_report_1.bin");
        let attester = TdxAttester::default();
        let rtmr_index = attester.pcr_to_ccmr(pcr_index) as usize - 1;

        let expected = hex::decode(expected).unwrap();
        let td_report = TdReport::read_from_bytes(report_bin).unwrap();

        assert_eq!(td_report.get_rtmr(rtmr_index), expected);
    }
}
