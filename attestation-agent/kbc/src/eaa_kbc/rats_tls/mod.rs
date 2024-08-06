// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use log::*;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::RawFd;
use std::ptr::NonNull;

mod ffi;
use ffi::*;

pub const MAX_FRAG_LENGTH: usize = 16384;

pub struct RatsTlsRef(Opaque);

unsafe impl ForeignTypeRef for RatsTlsRef {
    type CType = rats_tls_handle;
}

#[derive(Clone)]
pub struct RatsTls(NonNull<rats_tls_handle>);

unsafe impl Send for RatsTls {}
unsafe impl Sync for RatsTls {}

unsafe impl ForeignType for RatsTls {
    type CType = rats_tls_handle;
    type Ref = RatsTlsRef;

    unsafe fn from_ptr(ptr: *mut rats_tls_handle) -> RatsTls {
        RatsTls(NonNull::new(ptr).expect("rats_tls_handle ptr is null!"))
    }

    fn as_ptr(&self) -> *mut rats_tls_handle {
        self.0.as_ptr()
    }

    fn into_ptr(self) -> *mut rats_tls_handle {
        let inner = self.as_ptr();
        ::core::mem::forget(self);
        inner
    }
}

impl Drop for RatsTls {
    fn drop(&mut self) {
        unsafe {
            rats_tls_cleanup(self.as_ptr());
        }
    }
}

impl Deref for RatsTls {
    type Target = RatsTlsRef;

    fn deref(&self) -> &RatsTlsRef {
        unsafe { RatsTlsRef::from_ptr(self.as_ptr()) }
    }
}

impl DerefMut for RatsTls {
    fn deref_mut(&mut self) -> &mut RatsTlsRef {
        unsafe { RatsTlsRef::from_ptr_mut(self.as_ptr()) }
    }
}

impl RatsTls {
    pub fn new() -> Result<RatsTls, RatsTlsErrT> {
        let mut conf = rats_tls_conf_t {
            api_version: RATS_TLS_API_VERSION_DEFAULT,
            log_level: RATS_TLS_LOG_LEVEL_DEBUG,
            cert_algo: RATS_TLS_CERT_ALGO_DEFAULT,
            enclave_id: 0,
            ..Default::default()
        };
        conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

        let mut handle: rats_tls_handle = unsafe { std::mem::zeroed() };
        let mut tls: *mut rats_tls_handle = &mut handle;
        let err = unsafe { rats_tls_init(&conf, &mut tls) };
        if err != RATS_TLS_ERR_NONE {
            error!("rats_tls_init() failed");
            return Err(err);
        }

        let err = unsafe { rats_tls_set_verification_callback(&mut tls, None) };
        if err == RATS_TLS_ERR_NONE {
            Ok(unsafe { RatsTls::from_ptr(tls) })
        } else {
            Err(err)
        }
    }

    pub fn negotiate(&self, fd: RawFd) -> Result<(), RatsTlsErrT> {
        let err = unsafe { rats_tls_negotiate(self.as_ptr(), fd) };
        if err == RATS_TLS_ERR_NONE {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn receive(&self, buf: &mut [u8]) -> Result<usize, RatsTlsErrT> {
        let mut len: SizeT = buf.len() as SizeT;
        let err = unsafe {
            rats_tls_receive(
                self.as_ptr(),
                buf.as_mut_ptr() as *mut ::std::os::raw::c_void,
                &mut len,
            )
        };
        if err == RATS_TLS_ERR_NONE {
            Ok(len as usize)
        } else {
            Err(err)
        }
    }

    pub fn transmit(&self, buf: &[u8]) -> Result<usize, RatsTlsErrT> {
        let mut len: SizeT = buf.len() as SizeT;
        let err = unsafe {
            rats_tls_transmit(
                self.as_ptr(),
                buf.as_ptr() as *const ::std::os::raw::c_void,
                &mut len,
            )
        };
        if err == RATS_TLS_ERR_NONE {
            Ok(len as usize)
        } else {
            Err(err)
        }
    }

    #[no_mangle]
    extern "C" fn callback(_evidence: *mut ::std::os::raw::c_void) -> ::std::os::raw::c_int {
        info!("EAA KBC Rats-TLS callback function is unimplement!.");
        0
    }
}
