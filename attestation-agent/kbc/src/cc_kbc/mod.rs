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
        let key_data = self.kbs_client.get_resource(annotation_packet.kid).await?;
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
        let data = self.kbs_client.get_resource(desc).await?;

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

#[cfg(test)]
mod tests {
    use super::ResourceUri;
    use crate::cc_kbc::Kbc;

    const RESOURCE_URL_PORT: &str = "kbs://127.0.0.1:8081/alice/cosign-key/213";
    const RESOURCE_URL_NO_PORT: &str = "kbs://127.0.0.1/alice/cosign-key/213";
    const RESOURCE_NO_HOST_URL: &str = "kbs:///alice/cosign-key/213";

    const KBS_URL_PORT: &str = "https://127.0.0.1:8081";
    const KBS_URL_NO_PORT: &str = "https://127.0.0.1";
    const KBS_INVALID_URL: &str = "kbs:///alice/cosign-key/213";

    const RESOURCE_KBS_URL_PORT: &str =
        "https://127.0.0.1:8081/kbs/v0/resource/alice/cosign-key/213";
    const RESOURCE_KBS_URL_NO_PORT: &str = "https://127.0.0.1/kbs/v0/resource/alice/cosign-key/213";

    #[test]
    fn new_invalid_uri() {
        let kbc = Kbc::new(KBS_INVALID_URL.to_string());
        assert!(kbc.is_err());
    }

    #[test]
    fn new_valid_uri() {
        let kbc = Kbc::new(KBS_URL_PORT.to_string());
        assert!(kbc.is_ok());
    }

    fn to_kbs_uri(kbs_url: &str, resource_url: &str, expected_kbs_url: &str) {
        let resource: ResourceUri =
            serde_json::from_str(&format!("\"{resource_url}\"")).expect("deserialize failed");

        let kbc = Kbc::new(kbs_url.to_string());
        assert!(kbc.is_ok());

        println!(
            "{} {:?}",
            resource.kbs_addr,
            kbc.as_ref().unwrap().kbs_uri()
        );
        let resource_kbs_url = kbc.unwrap().resource_to_kbs_uri(&resource);

        assert!(resource_kbs_url.is_ok());
        assert_eq!(resource_kbs_url.unwrap(), expected_kbs_url);
    }

    #[test]
    fn resource_port_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_URL_PORT, RESOURCE_KBS_URL_PORT);
    }

    #[test]
    fn resource_no_port_to_kbs_uri() {
        to_kbs_uri(
            KBS_URL_NO_PORT,
            RESOURCE_URL_NO_PORT,
            RESOURCE_KBS_URL_NO_PORT,
        );
    }

    #[test]
    fn resource_no_host_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_NO_HOST_URL, RESOURCE_KBS_URL_PORT);
    }
}
