// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub const __BOOL_TRUE_FALSE_ARE_DEFINED: u32 = 1;
pub const _STDINT_H: u32 = 1;
pub const _FEATURES_H: u32 = 1;
pub const _DEFAULT_SOURCE: u32 = 1;
pub const __USE_ISOC11: u32 = 1;
pub const __USE_ISOC99: u32 = 1;
pub const __USE_ISOC95: u32 = 1;
pub const __USE_POSIX_IMPLICITLY: u32 = 1;
pub const _POSIX_SOURCE: u32 = 1;
pub const _POSIX_C_SOURCE: u32 = 200809;
pub const __USE_POSIX: u32 = 1;
pub const __USE_POSIX2: u32 = 1;
pub const __USE_POSIX199309: u32 = 1;
pub const __USE_POSIX199506: u32 = 1;
pub const __USE_XOPEN2K: u32 = 1;
pub const __USE_XOPEN2K8: u32 = 1;
pub const _ATFILE_SOURCE: u32 = 1;
pub const __USE_MISC: u32 = 1;
pub const __USE_ATFILE: u32 = 1;
pub const __USE_FORTIFY_LEVEL: u32 = 0;
pub const _STDC_PREDEF_H: u32 = 1;
pub const __STDC_IEC_559__: u32 = 1;
pub const __STDC_IEC_559_COMPLEX__: u32 = 1;
pub const __STDC_ISO_10646__: u32 = 201605;
pub const __STDC_NO_THREADS__: u32 = 1;
pub const __GNU_LIBRARY__: u32 = 6;
pub const __GLIBC__: u32 = 2;
pub const __GLIBC_MINOR__: u32 = 24;
pub const _SYS_CDEFS_H: u32 = 1;
pub const __WORDSIZE: u32 = 64;
pub const __WORDSIZE_TIME64_COMPAT32: u32 = 1;
pub const __SYSCALL_WORDSIZE: u32 = 64;
pub const _BITS_WCHAR_H: u32 = 1;
pub const RATS_TLS_API_VERSION_DEFAULT: u32 = 1;
pub const RATS_TLS_CONF_FLAGS_MUTUAL: u64 = 1;
pub const RATS_TLS_ERR_NONE: RatsTlsErrT = 0;
pub type RatsTlsErrT = ::std::os::raw::c_uint;
pub type SizeT = ::std::os::raw::c_ulong;
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Default, Copy, Clone)]
pub struct max_align_t {
    pub __clang_max_align_nonce1: ::std::os::raw::c_longlong,
    pub __bindgen_padding_0: u64,
    pub __clang_max_align_nonce2: u128,
}

pub const RATS_TLS_LOG_LEVEL_DEBUG: RatsTlsLogLevelT = 0;
pub const RATS_TLS_LOG_LEVEL_DEFAULT: RatsTlsLogLevelT = 3;
pub type RatsTlsLogLevelT = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_handle {
    _unused: [u8; 0],
}
pub const RATS_TLS_CERT_ALGO_DEFAULT: RatsTlsCertAlgoT = 1;
pub type RatsTlsCertAlgoT = ::std::os::raw::c_uint;
pub type QuoteSgxEcdsaVerificationTypeT = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_conf_t {
    pub api_version: ::std::os::raw::c_uint,
    pub flags: ::std::os::raw::c_ulong,
    pub log_level: RatsTlsLogLevelT,
    pub tls_type: [::std::os::raw::c_uchar; 32usize],
    pub attester_type: [::std::os::raw::c_uchar; 32usize],
    pub verifier_type: [::std::os::raw::c_uchar; 32usize],
    pub crypto_type: [::std::os::raw::c_uchar; 32usize],
    pub cert_algo: RatsTlsCertAlgoT,
    pub enclave_id: ::std::os::raw::c_ulonglong,
    pub quote_sgx_epid: rats_tls_conf_t__bindgen_ty_1,
    pub quote_sgx_ecdsa: rats_tls_conf_t__bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct rats_tls_conf_t__bindgen_ty_1 {
    pub valid: bool,
    pub spid: [u8; 16usize],
    pub linkable: bool,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rats_tls_conf_t__bindgen_ty_2 {
    pub valid: bool,
    pub cert_type: u8,
    pub verification_type: QuoteSgxEcdsaVerificationTypeT,
}

impl Default for rats_tls_conf_t__bindgen_ty_2 {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl Default for rats_tls_conf_t {
    fn default() -> Self {
        let mut conf: rats_tls_conf_t = unsafe { ::std::mem::zeroed() };
        conf.log_level = RATS_TLS_LOG_LEVEL_DEFAULT;
        conf
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtls_sgx_evidence {
    pub mr_enclave: *mut u8,
    pub mr_signer: *mut u8,
    pub product_id: u32,
    pub security_version: u32,
    pub attributes: *mut u8,
    pub collateral_size: SizeT,
    pub collateral: *mut ::std::os::raw::c_char,
}

pub type RtlsSgxEvidenceT = rtls_sgx_evidence;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtls_tdx_evidence {}

pub type RtlsTdxEvidenceT = rtls_tdx_evidence;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ehd {
    pub public_key: *mut ::std::os::raw::c_void,
    pub user_data_size: ::std::os::raw::c_int,
    pub user_data: *mut ::std::os::raw::c_char,
    pub unhashed_size: ::std::os::raw::c_int,
    pub unhashed: *mut ::std::os::raw::c_char,
}

pub type EhdT = ehd;
pub type EnclaveEvidenceTypeT = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct rtls_evidence {
    pub type_: EnclaveEvidenceTypeT,
    pub ehd: EhdT,
    pub quote_size: ::std::os::raw::c_int,
    pub quote: *mut ::std::os::raw::c_char,
    pub __bindgen_anon_1: rtls_evidence__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union rtls_evidence__bindgen_ty_1 {
    pub sgx: RtlsSgxEvidenceT,
    pub tdx: RtlsTdxEvidenceT,
}

pub type RatsTlsCallbackT = ::std::option::Option<
    unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void) -> ::std::os::raw::c_int,
>;

extern "C" {
    pub fn rats_tls_init(
        conf: *const rats_tls_conf_t,
        handle: *mut *mut rats_tls_handle,
    ) -> RatsTlsErrT;

    pub fn rats_tls_set_verification_callback(
        handle: *mut *mut rats_tls_handle,
        user_callback: RatsTlsCallbackT,
    ) -> RatsTlsErrT;

    pub fn rats_tls_negotiate(
        handle: *const rats_tls_handle,
        fd: ::std::os::raw::c_int,
    ) -> RatsTlsErrT;

    pub fn rats_tls_receive(
        handle: *const rats_tls_handle,
        buf: *mut ::std::os::raw::c_void,
        buf_size: *mut SizeT,
    ) -> RatsTlsErrT;

    pub fn rats_tls_transmit(
        handle: *const rats_tls_handle,
        buf: *const ::std::os::raw::c_void,
        buf_size: *mut SizeT,
    ) -> RatsTlsErrT;

    pub fn rats_tls_cleanup(handle: *mut rats_tls_handle) -> RatsTlsErrT;
}
