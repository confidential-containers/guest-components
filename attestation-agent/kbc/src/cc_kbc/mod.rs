// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::{decrypt, WrapType};
use kbs_protocol::{
    client::KbsClient,
    evidence_provider::{EvidenceProvider, NativeEvidenceProvider},
    KbsClientBuilder, KbsClientCapabilities,
};

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use zeroize::Zeroizing;

pub struct Kbc {
    token: Option<String>,
    kbs_client: KbsClient<Box<dyn EvidenceProvider>>,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key_data = self
            .kbs_client
            .get_resource(annotation_packet.kid, "resource".to_string())
            .await?;
        let key = Zeroizing::new(key_data);

        let wrap_type = WrapType::try_from(&annotation_packet.wrap_type[..])?;
        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            wrap_type,
        )
    }

    async fn get_resource(&mut self, desc: ResourceUri) -> Result<Vec<u8>> {
        let data = self
            .kbs_client
            .get_resource(desc, "resource".to_string())
            .await?;

        Ok(data)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        let kbs_client = KbsClientBuilder::with_evidence_provider(
            Box::new(NativeEvidenceProvider::new()?),
            &kbs_uri,
        )
        .build()?;
        Ok(Kbc {
            token: None,
            kbs_client,
        })
    }
}
