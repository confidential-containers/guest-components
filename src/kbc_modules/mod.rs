// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use self::annotation_packet::AnnotationPacket;
use self::uri::ResourceUri;

// Add your specific kbc declaration here.
// For example: "pub mod sample_kbc;"
#[allow(dead_code)]
#[cfg(feature = "cc_kbc")]
pub mod cc_kbc;

#[cfg(feature = "eaa_kbc")]
pub mod eaa_kbc;

#[cfg(feature = "offline_fs_kbc")]
pub mod offline_fs_kbc;

#[cfg(feature = "offline_sev_kbc")]
pub mod offline_sev_kbc;

#[cfg(feature = "online_sev_kbc")]
pub mod online_sev_kbc;

#[cfg(feature = "sample_kbc")]
pub mod sample_kbc;

pub mod annotation_packet;
pub mod uri;

// KbcInterface is a standard interface that all KBC modules need to implement.
#[async_trait]
pub trait KbcInterface: Send {
    /// Get information about KBC plugin.
    fn check(&self) -> Result<KbcCheckInfo>;

    /// Decrypt module specific encrypted payload into plaintext in asynchronous mode.
    /// The reason why this interface consumes the [`AnnotationPacket`] instead of simply
    /// return the key by key id is that some potential KBCs which use specific KMS can not
    /// return the key, and the actual decryption process occurs in the KMS.
    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>>;

    /// Get resources managed by the attestation agent in asynchronous mode.
    async fn get_resource(&mut self, _rid: ResourceUri) -> Result<Vec<u8>> {
        bail!("Get Resource API of this KBC is unimplement!")
    }
}

/// A container type for [KbcInterface] trait objects.
pub type KbcInstance = Box<dyn KbcInterface + Sync + Send>;

/// Status information about KBC modules.
pub struct KbcCheckInfo {
    pub kbs_info: HashMap<String, String>,
    // In the future, more KBC status fields will be expanded here.
}

type KbcInstantiateFunc = Box<dyn Fn(String) -> KbcInstance + Send + Sync>;

/// A container type to host all registered KBC modules.
pub struct KbcModuleList {
    mod_list: HashMap<String, KbcInstantiateFunc>,
}

impl KbcModuleList {
    /// Create a new [KbcModuleList] and register all known KBC modules.
    pub fn new() -> KbcModuleList {
        let mut mod_list = HashMap::new();

        #[cfg(feature = "sample_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(sample_kbc::SampleKbc::new(kbs_uri))
            });
            mod_list.insert("sample_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "cc_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(cc_kbc::Kbc::new(kbs_uri).unwrap())
            });
            mod_list.insert("cc_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "offline_fs_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|_: String| -> KbcInstance {
                Box::new(offline_fs_kbc::OfflineFsKbc::new())
            });
            mod_list.insert("offline_fs_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "eaa_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(eaa_kbc::EAAKbc::new(kbs_uri))
            });
            mod_list.insert("eaa_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "offline_sev_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|_: String| -> KbcInstance {
                Box::new(offline_sev_kbc::OfflineSevKbc::new())
            });
            mod_list.insert("offline_sev_kbc".to_string(), instantiate_func);
        }

        #[cfg(feature = "online_sev_kbc")]
        {
            let instantiate_func: KbcInstantiateFunc = Box::new(|kbs_uri: String| -> KbcInstance {
                Box::new(online_sev_kbc::OnlineSevKbc::new(kbs_uri))
            });
            mod_list.insert("online_sev_kbc".to_string(), instantiate_func);
        }

        KbcModuleList { mod_list }
    }

    /// Get initialization function for a KBC module.
    pub fn get_func(&self, kbc_name: &str) -> Result<&KbcInstantiateFunc> {
        let instantiate_func: &KbcInstantiateFunc =
            self.mod_list.get(kbc_name).ok_or_else(|| {
                anyhow!(
                    "AA does not support the given KBC module! Module: {}",
                    kbc_name
                )
            })?;
        Ok(instantiate_func)
    }

    pub fn names(&self) -> Vec<String> {
        self.mod_list.keys().cloned().collect()
    }
}

/// Descriptor for resources managed by attestation agent.
#[derive(Serialize, Deserialize, Debug)]
pub struct ResourceDescription {
    name: String,
    optional: HashMap<String, String>,
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
        /// by simple signing when doing iamge signature verification
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

        /// client ID used in online sev kbc
        #[strum(serialize = "kbs:///default/client-id/test")]
        ClientId,
    }
}
