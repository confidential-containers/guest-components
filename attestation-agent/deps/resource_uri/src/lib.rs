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
pub const DEFAULT_RESOURCE_PLUGIN: &str = "resource";

/// Resource Id document <https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/RESOURCE_URI.md>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUri {
    pub kbs_address: String,
    pub plugin: String,
    pub path: Vec<String>,
    pub query: Option<String>,
}

/// This three section segment is used to identify the resource in the KBS.
/// This is the useful when the plugin is `resource`, that means a confidential
/// resource inside the KBS.
///
/// - repo: the repository name
/// - r#type: the resource type
/// - tag: the resource tag
pub struct ResourcePluginPath {
    pub repo: String,
    pub r#type: String,
    pub tag: String,
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
        let mut kbs_address = value.host_str().unwrap_or_default().to_string();

        if !kbs_address.is_empty() {
            if let Some(port) = value.port() {
                kbs_address += ":";
                kbs_address += &port.to_string();
            }
        }

        let scheme = value.scheme();

        let plugin = match scheme {
            SCHEME => DEFAULT_RESOURCE_PLUGIN.to_string(),
            s if s.starts_with("kbs+") => {
                let plugin_name = s.trim_start_matches("kbs+");
                if plugin_name.is_empty() {
                    return Err("scheme kbs+ requires a plugin name, e.g. kbs+pkcs11");
                }
                plugin_name.to_string()
            }
            _ => return Err("scheme must be kbs or kbs+<plugin>"),
        };

        if value.path().is_empty() {
            return Err(RESOURCE_ID_ERROR_INFO);
        }

        let path = &value.path()[1..];
        let segments: Vec<String> = path.split('/').map(|s| s.to_string()).collect();

        Ok(Self {
            kbs_address,
            path: segments,
            query: value.query().map(|s| s.to_string()),
            plugin,
        })
    }
}

impl From<ResourceUri> for url::Url {
    fn from(val: ResourceUri) -> Self {
        url::Url::try_from(&val.whole_uri()[..]).expect("unexpected parse")
    }
}

impl TryFrom<ResourceUri> for ResourcePluginPath {
    type Error = anyhow::Error;
    fn try_from(value: ResourceUri) -> Result<Self, Self::Error> {
        if value.plugin != DEFAULT_RESOURCE_PLUGIN {
            bail!(
                "resource uri plugin must be {} instead of {}",
                DEFAULT_RESOURCE_PLUGIN,
                value.plugin
            );
        }

        if value.path.len() != 3 {
            bail!(
                "resource uri path must be 3 instead of {}",
                value.path.len()
            );
        }

        Ok(ResourcePluginPath {
            repo: value.path[0].clone(),
            r#type: value.path[1].clone(),
            tag: value.path[2].clone(),
        })
    }
}

impl ResourceUri {
    pub fn new(
        kbs_uri: &str,
        resource_path: &str,
        plugin: Option<&str>,
        query: Option<&str>,
    ) -> Result<Self> {
        let kbs_address = match url::Url::parse(kbs_uri) {
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

        let segments: Vec<String> = resource_path.split('/').map(|s| s.to_string()).collect();

        Ok(Self {
            kbs_address,
            path: segments,
            query: query.map(|s| s.to_string()),
            plugin: plugin.unwrap_or(DEFAULT_RESOURCE_PLUGIN).to_string(),
        })
    }

    pub fn whole_uri(&self) -> String {
        let scheme = match self.plugin.as_str() {
            DEFAULT_RESOURCE_PLUGIN => SCHEME.to_string(),
            plugin => format!("{SCHEME}+{plugin}"),
        };
        let uri = format!(
            "{scheme}://{kbs_address}/{path}",
            kbs_address = self.kbs_address,
            path = self.resource_path(),
        );
        match &self.query {
            Some(q) => format!("{uri}?{q}"),
            None => uri,
        }
    }

    /// Returns the plugin name. If no plugin was specified in the URI,
    /// returns the default plugin "resource".
    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    /// Only return the resource path. This function is used
    /// currently because up to now the kbs-uri is given
    /// to create an AA instance.
    pub fn resource_path(&self) -> String {
        self.path.join("/")
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
        use crate::DEFAULT_RESOURCE_PLUGIN;

        let resource = ResourceUri {
            kbs_address: if url.contains("example.com") {
                "example.com:8080".into()
            } else {
                "".into()
            },
            path: vec![repository.into(), r#type.into(), tag.into()],
            query: query.map(|s| s.to_string()),
            plugin: plugin.unwrap_or(DEFAULT_RESOURCE_PLUGIN).to_string(),
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
        let url_from_resource: url::Url = resource.clone().into();
        assert_eq!(url_from_string, url_from_resource);

        // Conversion to ResourceUri
        let resource_from_url =
            ResourceUri::try_from(url_from_string).expect("failed to try from url");
        assert_eq!(resource_from_url, resource);
    }

    #[rstest]
    #[case("kbs:///repo/type/tag", "kbs+resource:///repo/type/tag")]
    fn test_resource_plugin_uri_equivalence(#[case] shorthand: &str, #[case] explicit: &str) {
        let from_shorthand: ResourceUri = shorthand.try_into().expect("parse shorthand");
        let from_explicit: ResourceUri = explicit.try_into().expect("parse explicit");
        assert_eq!(from_shorthand, from_explicit);
        assert_eq!(from_shorthand.whole_uri(), shorthand);
        assert_eq!(
            serde_json::to_string(&from_explicit).expect("serialize"),
            format!("\"{shorthand}\"")
        );
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
