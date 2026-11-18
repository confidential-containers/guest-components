// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};

use crate::{
    image::{Error, Result},
    kbc::KbcClient,
};

/// `AnnotationPacket` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/attestation-agent/issues/113>
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: ResourceUri,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

impl AnnotationPacket {
    pub(crate) async fn unwrap_key(&self, kbc_client: Arc<KbcClient>) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use crypto::WrapType;

        let wrap_type = WrapType::try_from(&self.wrap_type[..])
            .map_err(|_| Error::UnknownWrapType(self.wrap_type.to_string()))?;
        let name = self.kid.whole_uri();
        let kek = kbc_client
            .get_resource(&name)
            .await
            .map_err(|e| Error::KbcClientError {
                context: "get KEK failed",
                source: e,
            })?;

        let lek = crypto::decrypt(
            kek.into(),
            STANDARD
                .decode(&self.wrapped_data)
                .map_err(|e| Error::Base64DecodeFailed {
                    context: "decode `wrapped_data`",
                    source: e,
                })?,
            STANDARD
                .decode(&self.iv)
                .map_err(|e| Error::Base64DecodeFailed {
                    context: "decode `iv`",
                    source: e,
                })?,
            wrap_type,
        )
        .map_err(|e| Error::DecryptFailed { source: e })?;

        Ok(lek)
    }
}
