// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};

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
    pub(crate) async fn unwrap_key(&self) -> crate::Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use crypto::WrapType;
        use kms::{plugins::VaultProvider, Annotations, ProviderSettings};

        use crate::Error;

        let wrap_type = WrapType::try_from(&self.wrap_type[..])
            .map_err(|e| Error::UnwrapAnnotationV1Failed(format!("parse WrapType failed: {e}")))?;
        let mut kbs_client =
            kms::new_getter(VaultProvider::Kbs.as_ref(), ProviderSettings::default())
                .await
                .map_err(|e| Error::UnwrapAnnotationV1Failed(format!("create kbc failed: {e}")))?;
        let name = self.kid.whole_uri();
        let kek = kbs_client
            .get_secret(&name, &Annotations::default())
            .await
            .map_err(|e| Error::UnwrapAnnotationV1Failed(format!("get KEK failed: {e}")))?;

        let lek = crypto::decrypt(
            kek.into(),
            STANDARD.decode(&self.wrapped_data).map_err(|e| {
                Error::UnwrapAnnotationV1Failed(format!("base64 decode `wrapped_data` failed: {e}"))
            })?,
            STANDARD.decode(&self.iv).map_err(|e| {
                Error::UnwrapAnnotationV1Failed(format!("base64 decode `iv` failed: {e}"))
            })?,
            wrap_type,
        )
        .map_err(|e| {
            Error::UnwrapAnnotationV1Failed(format!("decrypt LEK using KEK failed: {e}"))
        })?;
        Ok(lek)
    }
}
