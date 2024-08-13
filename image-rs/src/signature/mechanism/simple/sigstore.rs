// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use oci_client::Reference;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use tokio::fs;

use crate::signature::image;

// Format the sigstore name:
// `image-repository@digest-algorithm=digest-value`
pub fn format_sigstore_name(image_ref: &Reference, image_digest: image::digest::Digest) -> String {
    let image_name = image_ref.repository().to_string();
    format!(
        "{}@{}={}",
        image_name,
        image_digest.algorithm(),
        image_digest.value()
    )
}

// Defines sigstore locations (sigstore base url) for a single namespace.
// Please refer to https://github.com/containers/image/blob/main/docs/containers-registries.d.5.md for more details.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone, Eq)]
pub struct SigstoreConfig {
    #[serde(rename = "default-docker")]
    default_config: Option<SigstoreConfigEntry>,
    // The key is a namespace, using fully-expanded Docker reference format or parent namespaces.
    #[serde(rename = "docker")]
    docker_namespace_config: Option<HashMap<String, SigstoreConfigEntry>>,
}

impl SigstoreConfig {
    // loads sigstore configuration files(.yaml files) in specific dir.
    pub async fn new_from_configs(dir: &str) -> Result<Self> {
        let mut merged_config = SigstoreConfig::default();
        let yaml_extension = OsStr::new("yaml");

        let mut dirs = fs::read_dir(dir)
            .await
            .map_err(|e| anyhow!("Read Sigstore config Dir failed: {:?}, path: {}", e, dir))?;

        while let Some(entry) = dirs.next_entry().await? {
            let path = entry.path();
            if path.is_dir() || path.extension() != Some(yaml_extension) {
                continue;
            }
            let path_str = path
                .to_str()
                .ok_or_else(|| anyhow!("Unknown error: path parsed failed."))?;
            let config_yaml_string = fs::read_to_string(path_str).await?;
            let config = serde_yaml::from_str::<SigstoreConfig>(&config_yaml_string)?;

            // The "default-docker" only allowed to be defined in one config file.
            merged_config.update_self(config)?;
        }

        Ok(merged_config)
    }

    /// Update current [`SigstoreConfig`] using another [`SigstoreConfig`].
    /// - If current [`SigstoreConfig`] does not have a `default_config` but the input [`SigstoreConfig`]
    ///   has one, the current [`SigstoreConfig`] will use the input one's `default_config`.
    /// - If no duplicated `docker_namespace_config` is found in the input  [`SigstoreConfig`],
    ///   the current [`SigstoreConfig`] will be added all the input one's `docker_namespace_config`.
    ///   Any error will cause the update fail, and roll back to the original state.
    pub fn update_self(&mut self, input: SigstoreConfig) -> Result<()> {
        let mut merged_config = self.clone();
        // The "default-docker" only allowed to be defined in one config file.
        if input.default_config.is_some() {
            if merged_config.default_config.is_some()
                && input.default_config != merged_config.default_config
            {
                bail!("Error parsing sigstore config: \"default-docker\" defined repeatedly but differently.");
            }
            merged_config.default_config = input.default_config;
        }

        // Different SigstoreConfigEntry of same namespace is not allowed to appear in two different configuration files.
        if let Some(docker_config_map) = input.docker_namespace_config {
            for (ns_name, ns_config) in docker_config_map.iter() {
                if let Some(namespace) = merged_config.get_namespace(ns_name) {
                    if namespace != ns_config {
                        bail!(
                            "Error parsing sigstore config: {} defined repeatedly.",
                            &ns_name
                        );
                    }
                    continue;
                }

                merged_config.insert(ns_name, ns_config);
            }
        }

        *self = merged_config;
        Ok(())
    }

    fn get_namespace(&self, ns: &str) -> Option<&SigstoreConfigEntry> {
        if let Some(docker) = &self.docker_namespace_config {
            docker.get(ns)
        } else {
            None
        }
    }

    fn insert(&mut self, ns_name: &str, ns_config: &SigstoreConfigEntry) {
        if let Some(docker) = &mut self.docker_namespace_config {
            docker.insert(ns_name.to_string(), ns_config.clone());
        } else {
            let mut new_docker = HashMap::new();
            new_docker.insert(ns_name.to_string(), ns_config.clone());
            self.docker_namespace_config = Some(new_docker)
        }
    }

    // returns an URL string (sigstore base url) configured in sigstore config for the image.
    pub fn base_url(&self, image_ref: &Reference) -> Result<Option<String>> {
        if let Some(docker_config_map) = &self.docker_namespace_config {
            // Look for a full match.
            let image_id = image_ref.whole();
            // Look for a match of the possible parent namespaces.
            let mut image_ns = image::get_image_namespaces(image_ref);

            image_ns.insert(0, image_id);
            for ns in image_ns.iter() {
                if let Some(base_url) = docker_config_map.get(ns) {
                    return Ok(Some(base_url.sigstore.to_string()));
                }
            }
        }

        // Look for a default location
        if let Some(default_config) = &self.default_config {
            return Ok(Some(default_config.sigstore.to_string()));
        }

        Ok(None)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
struct SigstoreConfigEntry {
    sigstore: String,
}

pub async fn get_sigs_from_specific_sigstore(sigstore_uri: url::Url) -> Result<Vec<Vec<u8>>> {
    let mut res: Vec<Vec<u8>> = Vec::new();

    // FIXME: Now only support get signatures from local files.
    // only the uri with "file" scheme can be parsed.
    //
    // issue: https://github.com/confidential-containers/image-rs/issues/9
    match sigstore_uri.scheme() {
        "file" => {
            let sigstore_dir_path = sigstore_uri.path().to_string();
            let mut dirs = fs::read_dir(&sigstore_dir_path).await.map_err(|e| {
                anyhow!(
                    "Read Sigstore Dir failed: {:?}, path: {}",
                    e,
                    &sigstore_dir_path
                )
            })?;
            while let Some(entry) = dirs.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    continue;
                }
                let path_str = path
                    .to_str()
                    .ok_or_else(|| anyhow!("Unknown error: path parsed failed."))?;
                let sig = fs::read(path_str).await.map_err(|e| {
                    anyhow!("Read signature file failed: {:?}, path: {}", e, path_str)
                })?;
                res.push(sig);
            }
        }
        // TODO: support "https://" and other sigstore url.
        //
        // issue: https://github.com/confidential-containers/image-rs/issues/9
        _ => {
            bail!("HTTP support for signature stores is not implemented.");
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_client::Reference;
    use std::convert::TryFrom;
    use std::env;
    use std::fs;

    use image::digest::Digest;

    #[tokio::test]
    async fn test_get_sigs_from_specific_sigstore() {
        let current_dir = env::current_dir().expect("not found path");
        let test_sigstore_dir = format!(
            "file://{}/test_data/signature/signatures",
            current_dir.to_str().unwrap()
        );
        let test_sigstore_uri = url::Url::parse(test_sigstore_dir.as_str()).unwrap();
        assert!(get_sigs_from_specific_sigstore(test_sigstore_uri.clone())
            .await
            .is_ok());
        assert_eq!(
            2,
            get_sigs_from_specific_sigstore(test_sigstore_uri)
                .await
                .unwrap()
                .len()
        );
    }

    #[tokio::test]
    async fn test_get_sigstore_base_url() {
        #[derive(Debug)]
        struct TestData<'a> {
            reference: Reference,
            sigstore_base_url: &'a str,
        }

        let tests = &[
            TestData {
                reference: Reference::try_from("example1.com/mylib/busybox:latest").unwrap(),
                sigstore_base_url: "file:///var/lib/containers/sigstore",
            },
            TestData {
                reference: Reference::try_from("example3.com/mylib/busybox:latest").unwrap(),
                // Here `sigstore_base_url` is the default base url
                // because there isn't match with `example3.com` namespace
                sigstore_base_url: "file:///default/sigstore",
            },
        ];

        let test_sigstore_config_dir = "./test_data/signature/sigstore_config/get_base_url";
        let sigstore_config = SigstoreConfig::new_from_configs(test_sigstore_config_dir)
            .await
            .unwrap();

        for test_case in tests.iter() {
            assert_eq!(
                test_case.sigstore_base_url,
                &sigstore_config
                    .base_url(&test_case.reference)
                    .unwrap()
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_new_from_configs() {
        #[derive(Debug)]
        struct TestData<'a> {
            sigstore_config_path: &'a str,
            merged_res_path: &'a str,
        }

        let tests_expect = &[
            TestData {
                sigstore_config_path: "./test_data/signature/sigstore_config/test_case_3",
                merged_res_path: "./test_data/signature/sigstore_config/merged_result/res3.yaml",
            },
            TestData {
                sigstore_config_path: "./test_data/signature/sigstore_config/test_case_2",
                merged_res_path: "./test_data/signature/sigstore_config/merged_result/res2.yaml",
            },
            TestData {
                sigstore_config_path: "./test_data/signature/sigstore_config/test_case_1",
                merged_res_path: "./test_data/signature/sigstore_config/merged_result/res1.yaml",
            },
        ];

        for case in tests_expect.iter() {
            let merged_string = fs::read_to_string(case.merged_res_path).unwrap();
            let merged_config = serde_yaml::from_str::<SigstoreConfig>(&merged_string).unwrap();
            assert_eq!(
                merged_config,
                SigstoreConfig::new_from_configs(case.sigstore_config_path)
                    .await
                    .expect("new sigstore config from filesystem")
            );
        }
    }

    #[test]
    fn test_format_sigstore_name() {
        let image_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        #[derive(Debug)]
        struct TestData {
            reference: Reference,
            formatted_name: String,
        }

        let tests = &[
            TestData {
                reference: Reference::try_from("docker.io/library/busybox").unwrap(),
                formatted_name: "library/busybox@sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
            },
            TestData {
                reference: Reference::try_from("test:5000/mylib/busybox:tag").unwrap(),
                formatted_name: "mylib/busybox@sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
            }
        ];

        for case in tests.iter() {
            assert_eq!(
                case.formatted_name,
                format_sigstore_name(
                    &case.reference,
                    Digest::try_from(&image_digest.clone()[..]).unwrap()
                )
            );
        }
    }
}
