// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! ResourceUri is the identification information of all resources that need to be
//! obtained from `get_resource` endpoint. Also, `kid` field in an
//! [`super::AnnotationPacket`] of `decrypt_payload` should also follow this.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const RESOURCE_ID_ERROR_INFO: &str =
    "invalid kbs resource uri, should be kbs://<addr-of-kbs>/<repo>/<type>/<tag>";

const SCHEME: &str = "kbs";

/// Resource Id document <https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/KBS_URI.md>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUri {
    pub kbs_addr: String,
    pub repository: String,
    pub r#type: String,
    pub tag: String,
    pub query: Option<String>,
}

impl TryFrom<&str> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = url::Url::try_from(value).map_err(|_| RESOURCE_ID_ERROR_INFO)?;
        Self::try_from(url)
    }
}

impl TryFrom<url::Url> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: url::Url) -> Result<Self, Self::Error> {
        let mut addr = value.host_str().unwrap_or_default().to_string();

        if !addr.is_empty() {
            if let Some(port) = value.port() {
                addr += ":";
                addr += &port.to_string();
            }
        }

        if value.scheme() != SCHEME {
            return Err("scheme must be kbs");
        }

        if value.path().is_empty() {
            return Err(RESOURCE_ID_ERROR_INFO);
        }

        let path = &value.path()[1..];
        let values: Vec<&str> = path.split('/').collect();
        if values.len() == 3 {
            Ok(Self {
                kbs_addr: addr,
                repository: values[0].into(),
                r#type: values[1].into(),
                tag: values[2].into(),
                query: value.query().map(|s| s.to_string()),
            })
        } else {
            Err(RESOURCE_ID_ERROR_INFO)
        }
    }
}

impl From<ResourceUri> for url::Url {
    fn from(val: ResourceUri) -> Self {
        url::Url::try_from(&val.whole_uri()[..]).expect("unexpected parse")
    }
}

impl ResourceUri {
    pub fn new(kbs_uri: &str, resource_path: &str) -> Result<Self> {
        let kbs_addr = match url::Url::parse(kbs_uri) {
            Ok(url) => {
                let kbs_host = url
                    .host_str()
                    .ok_or_else(|| anyhow!("Invalid URL: {}", url))?;

                if let Some(port) = url.port() {
                    format!("{kbs_host}:{port}")
                } else {
                    kbs_host.to_string()
                }
            }
            Err(_) => kbs_uri.to_string(),
        };

        if !resource_path.starts_with('/') {
            bail!("Resource path {resource_path} must start with '/'")
        }

        let values: Vec<&str> = resource_path.split('/').collect();
        if values.len() == 4 {
            Ok(Self {
                kbs_addr,
                repository: values[1].into(),
                r#type: values[2].into(),
                tag: values[3].into(),
                query: None,
            })
        } else {
            bail!(
                "Resource path {resource_path} must follow the format '/<repository>/<type>/<tag>'"
            )
        }
    }

    pub fn whole_uri(&self) -> String {
        let uri = format!(
            "{SCHEME}://{}/{}/{}/{}",
            self.kbs_addr, self.repository, self.r#type, self.tag
        );
        match &self.query {
            Some(q) => format!("{uri}?{q}"),
            None => uri,
        }
    }

    /// Only return the resource path. This function is used
    /// currently because up to now the kbs-uri is given
    /// to create an AA instance.
    pub fn resource_path(&self) -> String {
        format!("{}/{}/{}", self.repository, self.r#type, self.tag)
    }
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let url = self.whole_uri();
        ser.serialize_str(&url)
    }
}

impl<'de> Deserialize<'de> for ResourceUri {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: &str = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceUri;
    use rstest::rstest;

    #[rstest]
    #[case("kbs:///alice/cosign-key/213", "alice", "cosign-key", "213", None)]
    #[case(
        "kbs:///a/b/c?param1=value1&param2=value2",
        "a",
        "b",
        "c",
        Some("param1=value1&param2=value2")
    )]
    fn test_resource_uri_serialization_conversion(
        #[case] url: &str,
        #[case] repository: &str,
        #[case] r#type: &str,
        #[case] tag: &str,
        #[case] query: Option<&str>,
    ) {
        let resource = ResourceUri {
            kbs_addr: "".into(),
            repository: repository.into(),
            r#type: r#type.into(),
            tag: tag.into(),
            query: query.map(|s| s.to_string()),
        };

        // Deserialization
        let deserialized: ResourceUri =
            serde_json::from_str(&format!("\"{url}\"")).expect("deserialize failed");
        assert_eq!(deserialized, resource);

        // Serialization
        let serialized = serde_json::to_string(&resource).expect("deserialize failed");
        assert_eq!(serialized, format!("\"{url}\""));

        // Conversion to Url
        let url_from_string = url::Url::try_from(url).expect("failed to parse url");
        let url_from_resource: url::Url =
            resource.clone().try_into().expect("failed to try into url");
        assert_eq!(url_from_string, url_from_resource);

        // Conversion to ResourceUri
        let resource_from_url =
            ResourceUri::try_from(url_from_string).expect("failed to try from url");
        assert_eq!(resource_from_url, resource);
    }
}
