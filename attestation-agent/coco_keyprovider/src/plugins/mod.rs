// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod kbs;

use anyhow::{bail, Result};
use image::AnnotationPacket;
use tonic::async_trait;

#[async_trait]
pub trait ImageEncrypter: Send + Sync {
    async fn encrypt_lek(
        &mut self,
        lek: &[u8],
        kek_id: Option<String>,
        kek: Option<Vec<u8>>,
    ) -> Result<AnnotationPacket>;
}

pub async fn init_image_encrypter(encryptor_name: &str) -> Result<Box<dyn ImageEncrypter>> {
    let encryptor = match encryptor_name {
        "kbs" => Box::new(kbs::Client::new().await?) as Box<dyn ImageEncrypter>,
        other => bail!("unsupported encrypter {other}"),
    };

    Ok(encryptor)
}
