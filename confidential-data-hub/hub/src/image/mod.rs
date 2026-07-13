// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod annotation_packet;
pub mod error;

pub use annotation_packet::AnnotationPacket;
use anyhow::anyhow;
pub use error::{Error, Result};

pub async fn unwrap_key(annotation_packet: &[u8]) -> Result<Vec<u8>> {
    let annotation_packet: AnnotationPacket =
        serde_json::from_slice(annotation_packet).map_err(|e| Error::ParseAnnotationPacket {
            source: anyhow!("deserialize failed, {e:?}"),
        })?;
    let lek = annotation_packet.unwrap_key().await?;

    Ok(lek)
}
