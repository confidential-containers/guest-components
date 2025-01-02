// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{Arc, LazyLock};

use anyhow::*;
use kbc::{cc_kbc::Kbc as CcKbc, sample_kbc::SampleKbc, AnnotationPacket, KbcInterface};
use tokio::sync::RwLock;

pub enum Kbc {
    Sample(SampleKbc),
    Cc(CcKbc),
}

pub static CHANNEL: LazyLock<Arc<RwLock<Option<Kbc>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

async fn initialize_channel(kbs_addr: &str, kbc: &str) -> Result<()> {
    let channel = match kbc {
        "cc_kbc" => Kbc::Cc(CcKbc::new(kbs_addr.to_owned())?),
        "sample_kbc" => Kbc::Sample(SampleKbc::new(kbs_addr.to_owned())),
        other => bail!("Unsupported KBC {other}"),
    };

    let mut writer = CHANNEL.write().await;
    *writer = Some(channel);
    Ok(())
}

pub async fn decrypt_image_layer_annotation(
    kbs_addr: &str,
    kbc: &str,
    annotation: &str,
) -> Result<Vec<u8>> {
    let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)?;

    // Sample KBC is still used in enclave-cc legacy e2e test. Native key provider
    // will still support this until it is decided to be depreciated.
    if CHANNEL.read().await.is_none() {
        initialize_channel(kbs_addr, kbc).await?;
    }

    let res = {
        let mut writer = CHANNEL.write().await;
        let writer = writer.as_mut().expect("unexpected uninitialized.");
        match writer {
            Kbc::Sample(inner) => inner.decrypt_payload(annotation_packet).await,
            Kbc::Cc(inner) => inner.decrypt_payload(annotation_packet).await,
        }
    }?;

    Ok(res)
}
