// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a new version of [`AnnotationPacket`] which is compatible with
//! the previous version.

use base64::{engine::general_purpose::STANDARD, Engine};
use kms::{plugins::VaultProvider, Annotations, ProviderSettings};
use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::{Error, Result};

const DEFAULT_VERSION: &str = "0.1.0";

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
    VaultProvider::Kbs.as_ref().to_string()
}

#[cfg(feature = "kbs")]
impl TryInto<super::v1::AnnotationPacket> for AnnotationPacketV2 {
    type Error = Error;

    fn try_into(self) -> std::result::Result<super::v1::AnnotationPacket, Self::Error> {
        if self.version != DEFAULT_VERSION {
            return Err(Error::ConvertAnnotationPacketFailed(format!(
                "`version` must be {DEFAULT_VERSION}."
            )));
        }

        if self.provider != VaultProvider::Kbs.as_ref() {
            return Err(Error::ConvertAnnotationPacketFailed(String::from(
                "Provider must be `kbs`.",
            )));
        }

        if self.wrap_type.is_none() {
            return Err(Error::ConvertAnnotationPacketFailed(String::from(
                "no `WrapType` given.",
            )));
        }

        if self.iv.is_none() {
            return Err(Error::ConvertAnnotationPacketFailed(String::from(
                "no `iv` given.",
            )));
        }

        let kid = resource_uri::ResourceUri::try_from(&self.kid[..]).map_err(|e| {
            Error::ConvertAnnotationPacketFailed(format!("illegal ResourceUri in `kid` field: {e}"))
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
            #[cfg(feature = "kbs")]
            "kbs" => {
                let anno_v1: super::v1::AnnotationPacket = self.clone().try_into()?;
                anno_v1.unwrap_key().await?
            }
            kms => {
                let mut kms_client = kms::new_decryptor(kms, self.provider_settings.clone())
                    .await
                    .map_err(|e| {
                        Error::UnwrapAnnotationV2Failed(format!("create KMS client failed: {e}"))
                    })?;

                kms_client
                    .decrypt(
                        &STANDARD.decode(&self.wrapped_data).map_err(|e| {
                            Error::UnwrapAnnotationV1Failed(format!(
                                "base64 decode `wrapped_data` failed: {e}"
                            ))
                        })?,
                        &self.kid,
                        &self.annotations,
                    )
                    .await
                    .map_err(|e| {
                        Error::UnwrapAnnotationV2Failed(format!("KMS decryption failed: {e}"))
                    })?
            }
        };
        Ok(lek)
    }
}
