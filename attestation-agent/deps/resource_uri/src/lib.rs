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
const DEFAULT_PLUGIN: &str = "resource";

/// Resource Id document <https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/RESOURCE_URI.md>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUri {
    pub kbs_addr: String,
    pub repository: String,
    pub r#type: String,
    pub tag: String,
    pub query: Option<String>,
    pub plugin: Option<String>,
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

        let scheme = value.scheme();

        let plugin = match scheme {
            SCHEME => None,
            s if s.starts_with("kbs+") => {
                let plugin_name = s.trim_start_matches("kbs+");
                if plugin_name.is_empty() {
                    return Err("scheme kbs+ requires a plugin name, e.g. kbs+pkcs11");
                }
                Some(plugin_name.to_string())
            }
            _ => return Err("scheme must be kbs or kbs+<plugin>"),
        };

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
                plugin,
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
                plugin: None,
            })
        } else {
            bail!(
                "Resource path {resource_path} must follow the format '/<repository>/<type>/<tag>'"
            )
        }
    }

    pub fn whole_uri(&self) -> String {
        let scheme = match &self.plugin {
            Some(p) => format!("{SCHEME}+{p}"),
            None => SCHEME.to_string(),
        };
        let uri = format!(
            "{scheme}://{}/{}/{}/{}",
            self.kbs_addr, self.repository, self.r#type, self.tag
        );
        match &self.query {
            Some(q) => format!("{uri}?{q}"),
            None => uri,
        }
    }

    /// Returns the plugin name. If no plugin was specified in the URI,
    /// returns the default plugin "resource".
    pub fn plugin(&self) -> &str {
        self.plugin.as_deref().unwrap_or(DEFAULT_PLUGIN)
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
    #[case(
        "kbs:///alice/cosign-key/213",
        "alice",
        "cosign-key",
        "213",
        None,
        None
    )]
    #[case(
        "kbs:///repo/type/tag?param1=value1&param2=value2",
        "repo",
        "type",
        "tag",
        Some("param1=value1&param2=value2"),
        None
    )]
    #[case(
        "kbs+pkcs11:///repo/type/tag",
        "repo",
        "type",
        "tag",
        None,
        Some("pkcs11")
    )]
    #[case("kbs+myplugin:///a/b/c", "a", "b", "c", None, Some("myplugin"))]
    #[case(
        "kbs+custom://example.com:8080/repo/type/tag",
        "repo",
        "type",
        "tag",
        None,
        Some("custom")
    )]
    fn test_resource_uri_serialization_conversion(
        #[case] url: &str,
        #[case] repository: &str,
        #[case] r#type: &str,
        #[case] tag: &str,
        #[case] query: Option<&str>,
        #[case] plugin: Option<&str>,
    ) {
        let resource = ResourceUri {
            kbs_addr: if url.contains("example.com") {
                "example.com:8080".into()
            } else {
                "".into()
            },
            repository: repository.into(),
            r#type: r#type.into(),
            tag: tag.into(),
            query: query.map(|s| s.to_string()),
            plugin: plugin.map(|s| s.to_string()),
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

    #[rstest]
    #[case("kbs:///repo/type/tag", "resource")]
    #[case("kbs+pkcs11:///repo/type/tag", "pkcs11")]
    fn test_plugin_accessor(#[case] uri: &str, #[case] plugin: &str) {
        let uri: ResourceUri = uri.try_into().expect("failed to parse uri");
        assert_eq!(uri.plugin(), plugin);
    }

    #[rstest]
    #[case("http:///repo/type/tag", "scheme must be kbs")]
    #[case("kbs+:///repo/type/tag", "requires a plugin name")]
    fn test_invalid_scheme(#[case] uri: &str, #[case] error: &str) {
        let result = ResourceUri::try_from(uri);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(error));
    }
}
