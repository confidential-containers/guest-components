// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::decrypt;

use kbs_protocol::{KbsProtocolWrapper, KbsRequest, KBS_PREFIX};

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use url::Url;
use zeroize::Zeroizing;

pub struct Kbc {
    kbs_uri: Url,
    token: Option<String>,
    kbs_protocol_wrapper: KbsProtocolWrapper,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key_url = self.resource_to_kbs_uri(&annotation_packet.kid)?;

        let key_data = self.kbs_protocol_wrapper().http_get(key_url).await?;
        let key = Zeroizing::new(key_data);

        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            &annotation_packet.wrap_type,
        )
    }

    #[allow(unused_assignments)]
    async fn get_resource(&mut self, desc: ResourceUri) -> Result<Vec<u8>> {
        let resource_url = self.resource_to_kbs_uri(&desc)?;
        let data = self.kbs_protocol_wrapper().http_get(resource_url).await?;

        Ok(data)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        // Check the KBS URI validity
        let url = Url::parse(&kbs_uri).map_err(|e| anyhow!("Invalid URI {kbs_uri}: {e}"))?;
        if !url.has_host() {
            bail!("{kbs_uri} is missing a host");
        }

        Ok(Kbc {
            kbs_uri: url,
            token: None,
            kbs_protocol_wrapper: KbsProtocolWrapper::new(vec![]).unwrap(),
        })
    }

    fn kbs_uri(&self) -> &str {
        self.kbs_uri.as_str().trim_end_matches('/')
    }

    fn kbs_protocol_wrapper(&mut self) -> &mut KbsProtocolWrapper {
        &mut self.kbs_protocol_wrapper
    }

    /// Convert a [`ResourceUri`] to a KBS URL.
    pub fn resource_to_kbs_uri(&self, resource: &ResourceUri) -> Result<String> {
        let kbs_host = self
            .kbs_uri
            .host_str()
            .ok_or_else(|| anyhow!("Invalid URL: {}", self.kbs_uri))?;

        let kbs_addr = if let Some(port) = self.kbs_uri.port() {
            format!("{kbs_host}:{port}")
        } else {
            kbs_host.to_string()
        };

        if !resource.kbs_addr.is_empty() && resource.kbs_addr != kbs_addr {
            bail!(
                "The resource KBS host {} differs from the KBS URL one {kbs_addr}",
                resource.kbs_addr
            );
        }

        let kbs_addr = self.kbs_uri();
        let repo = &resource.repository;
        let r#type = &resource.r#type;
        let tag = &resource.tag;
        Ok(format!(
            "{kbs_addr}{KBS_PREFIX}/resource/{repo}/{type}/{tag}"
        ))
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
