// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod rsa {
    #[cfg(feature = "openssl")]
    pub use crate::native::rsa::*;

    #[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
    pub use crate::rust::rsa::*;

    /// Definations of different Padding mode for encryption. Refer to
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-4.1> for
    /// more information.
    #[derive(EnumString, AsRefStr)]
    pub enum PaddingMode {
        #[strum(serialize = "RSA-OAEP")]
        OAEP,

        #[strum(serialize = "RSA1_5")]
        PKCS1v15,
    }

    pub const RSA_PUBKEY_LENGTH: usize = 2048;

    pub const RSA_KTY: &str = "RSA";
}
