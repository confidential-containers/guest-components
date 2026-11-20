// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a new version of [`AnnotationPacket`] which is compatible with
//! the previous version.

use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD, Engine};
use kms::{Annotations, ProviderSettings};
use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::image::{Error, Result};

pub const DEFAULT_PROVIDER: &str = "kbs";

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

fn default_provider() -> String {
    DEFAULT_PROVIDER.to_string()
}

fn default_version() -> String {
    DEFAULT_VERSION.to_string()
}

impl TryInto<super::v1::AnnotationPacket> for AnnotationPacketV2 {
    type Error = Error;

    fn try_into(self) -> std::result::Result<super::v1::AnnotationPacket, Self::Error> {
        if self.version != DEFAULT_VERSION {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("version` must be {DEFAULT_VERSION}."),
            });
        }

        if self.provider != DEFAULT_PROVIDER {
            return Err(Error::ParseAnnotationPacket {
                source: anyhow!("Provider must be `{DEFAULT_PROVIDER}`."),
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
    pub async fn unwrap_key(&self, kms_client: &mut Box<dyn kms::Decrypter>) -> Result<Vec<u8>> {
        let lek = kms_client
            .decrypt(
                &STANDARD
                    .decode(&self.wrapped_data)
                    .map_err(|e| Error::Base64DecodeFailed {
                        context: "base64 decode `wrapped_data`",
                        source: e,
                    })?,
                &self.kid,
                &self.annotations,
            )
            .await
            .map_err(|e| Error::KmsError {
                context: "decrypt LEK with KEK",
                source: e,
            })?;
        Ok(lek)
    }
}
