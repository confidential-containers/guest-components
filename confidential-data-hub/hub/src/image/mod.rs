// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod annotation_packet;
pub mod error;

use std::sync::Arc;

pub use annotation_packet::{AnnotationPacketV1, AnnotationPacketV2};
use anyhow::anyhow;
pub use error::{Error, Result};

use crate::kbc::KbcClient;

pub async fn unwrap_key(annotation_packet: &[u8], kbc_client: Arc<KbcClient>) -> Result<Vec<u8>> {
    let annotation_packet: AnnotationPacketV2 =
        serde_json::from_slice(annotation_packet).map_err(|e| Error::ParseAnnotationPacket {
            source: anyhow!("deserialize failed, {e:?}"),
        })?;
    let lek = match &annotation_packet.provider[..] {
        "kbs" => {
            let packet_v1: AnnotationPacketV1 = annotation_packet.try_into()?;

            packet_v1.unwrap_key(kbc_client).await?
        }
        others => {
            let mut kms_client =
                kms::new_decryptor(others, annotation_packet.provider_settings.clone())
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "create KMS client",
                        source: e,
                    })?;
            annotation_packet.unwrap_key(&mut kms_client).await?
        }
    };

    Ok(lek)
}
