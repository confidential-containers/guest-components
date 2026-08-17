// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate strum;

use anyhow::*;
use async_trait::async_trait;
use resource_uri::ResourceUri;

pub use self::annotation_packet::AnnotationPacket;

#[cfg(feature = "cc_kbc")]
pub mod cc_kbc;

pub mod offline_fs_kbc;
pub mod sample_kbc;

pub mod annotation_packet;

/// KbcInterface is a standard interface that all KBC modules need to implement.
#[async_trait]
pub trait KbcInterface: Send {
    /// Decrypt module specific encrypted payload into plaintext in asynchronous mode.
    /// The reason why this interface consumes the [`AnnotationPacket`] instead of simply
    /// return the key by key id is that some potential KBCs which use specific KMS can not
    /// return the key, and the actual decryption process occurs in the KMS.
    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>>;

    /// Get resources managed by the attestation agent in asynchronous mode.
    async fn get_resource(&mut self, _resource_uri: ResourceUri) -> Result<Vec<u8>> {
        bail!("Get Resource API of this KBC is unimplement!")
    }
}

pub mod tests {
    /// Type of resources supported by the attestation agent.
    /// The related serialize string is the resource uri for tests.
    #[derive(AsRefStr, EnumString, Display, Debug, PartialEq, Eq)]
    pub enum ResourcePath {
        /// image security policy, used to define whether a specific
        /// image can be pulled, or signature verification is needed
        #[strum(serialize = "kbs:///default/security-policy/test")]
        Policy,

        /// used to configure the storage path of public keys used
        /// by simple signing when doing image signature verification
        #[strum(serialize = "kbs:///default/sigstore-config/test")]
        SigstoreConfig,

        /// gpg public key used to verify signature of images in
        /// simple signing scheme.
        #[strum(serialize = "kbs:///default/gpg-public-config/test")]
        GPGPublicKey,

        /// public key file used to verify signature of images in
        /// cosign scheme.
        #[strum(serialize = "kbs:///default/cosign-public-key/test")]
        CosignVerificationKey,

        /// container registry auth file, used to provide auth
        /// when accessing a private registry / repository
        #[strum(serialize = "kbs:///default/credential/test")]
        Credential,
    }
}
