// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// This lint checker is for [`rsa::PaddingMode::PKCS1v15`]
// TODO: remove this when the deprecated attribute is removed
#[allow(deprecated)]
pub mod rsa {
    #[cfg(feature = "openssl")]
    pub use crate::native::rsa::*;

    #[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
    pub use crate::rust::rsa::*;

    /// Definitions of different Padding mode for encryption. Refer to
    /// <https://datatracker.ietf.org/doc/html/rfc7518#section-4.1> for
    /// more information.
    #[derive(EnumString, AsRefStr)]
    pub enum PaddingMode {
        /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
        #[strum(serialize = "RSA-OAEP-256")]
        OAEP,

        /// RSA PKCS#1 v1.5
        #[deprecated(note = "This algorithm is no longer recommended.")]
        #[strum(serialize = "RSA1_5")]
        PKCS1v15,
    }

    pub const RSA_PUBKEY_LENGTH: usize = 2048;

    pub const RSA_KTY: &str = "RSA";
}

pub mod ec {
    #[cfg(feature = "openssl")]
    pub use crate::native::ec::*;

    #[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
    pub use crate::rust::ec::*;

    /// The elliptic curve key type
    pub const EC_KTY: &str = "EC";

    /// Definitions of different key wrapping algorithms. Refer to
    /// <https://datatracker.ietf.org/doc/html/rfc7518> for
    /// more information.
    #[derive(EnumString, AsRefStr)]
    pub enum KeyWrapAlgorithm {
        /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
        #[strum(serialize = "ECDH-ES+A256KW")]
        EcdhEsA256Kw,
    }

    #[derive(EnumString, AsRefStr)]
    pub enum Curve {
        #[strum(serialize = "P-256")]
        P256,
    }
}
