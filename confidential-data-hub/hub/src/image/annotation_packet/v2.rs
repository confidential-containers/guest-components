// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a new version of [`AnnotationPacket`] which is compatible with
//! the previous version.

use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::image::{Error, Result};
use crate::kms;
use crate::kms::{plugins::VaultProvider, Annotations, ProviderSettings};

pub const DEFAULT_VERSION: &str = "0.1.0";

/// New version format of AnnotationPacket
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct AnnotationPacketV2 {
    /// Version of the AnnotationPacket
    #[serde(default = "default_version")]
    pub version: String,

    /// Key ID to manage multiple keys. If provider is `kbs`, this field
    /// should be a [`ResourceUri`]
    pub kid: String,

    /// Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,

    /// The way to decrypt this LEK, s.t. provider of the KEK.
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Initialisation vector (base64-encoded). Only used when
    /// provider is `"kbs"`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    /// Wrap type to specify encryption algorithm and mode. Only used when
    /// provider is `"kbs"`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_type: Option<String>,

    /// extra information to create a client
    #[serde(default = "Map::default")]
    pub provider_settings: ProviderSettings,

    /// KMS specific fields to locate the Key inside KMS
    #[serde(default = "Map::default")]
    pub annotations: Annotations,
}

fn default_version() -> String {
    DEFAULT_VERSION.to_string()
}

fn default_provider() -> String {
    VaultProvider::Kbs.as_ref().to_lowercase().to_string()
}

impl TryInto<super::v1::AnnotationPacket> for AnnotationPacketV2 {
    type Error = Error;

    fn try_into(self) -> std::result::Result<super::v1::AnnotationPacket, Self::Error> {
        if self.version != DEFAULT_VERSION {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("version` must be {DEFAULT_VERSION}."),
            });
        }

        if self.provider != VaultProvider::Kbs.as_ref().to_lowercase() {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("Provider must be `kbs`."),
            });
        }

        if self.wrap_type.is_none() {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("no `WrapType` given."),
            });
        }

        if self.iv.is_none() {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("no `iv` given."),
            });
        }

        let kid = resource_uri::ResourceUri::try_from(&self.kid[..]).map_err(|e| {
            Error::ParseAnnotationPacket {
                source: anyhow!("illegal ResourceUri in `kid` field: {e:?}"),
            }
        })?;

        let annotation_packet = super::v1::AnnotationPacket {
            kid,
            wrapped_data: self.wrapped_data,
            iv: self.iv.expect("must have `iv`"),
            wrap_type: self.wrap_type.expect("must have `wrap_type`"),
        };

        Ok(annotation_packet)
    }
}

impl AnnotationPacketV2 {
    pub async fn unwrap_key(&self) -> Result<Vec<u8>> {
        let lek = match &self.provider[..] {
            "kbs" => {
                let anno_v1: super::v1::AnnotationPacket = self.clone().try_into()?;
                anno_v1.unwrap_key().await?
            }
            kms => {
                let mut kms_client = kms::new_decryptor(kms, self.provider_settings.clone())
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "create KMS client",
                        source: e,
                    })?;

                kms_client
                    .decrypt(
                        &STANDARD.decode(&self.wrapped_data).map_err(|e| {
                            Error::Base64DecodeFailed {
                                context: "base64 decode `wrapped_data`",
                                source: e,
                            }
                        })?,
                        &self.kid,
                        &self.annotations,
                    )
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "decrypt LEK with KEK",
                        source: e,
                    })?
            }
        };
        Ok(lek)
    }
}
