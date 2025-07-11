// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is the registry configuration defined in
//! <https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md>
//! and
//! <https://www.redhat.com/en/blog/manage-container-registries>

use std::str::FromStr;

use anyhow::{bail, Result};
use log::debug;
use oci_client::Reference;
use serde::{Deserialize, Serialize};

use crate::image::{ImagePullTask, TaskType};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Mirror {
    /// The mirror location
    location: String,

    #[serde(default)]
    insecure: bool,
    // TODO: add pull_from_mirror options
}

/// Namespaced `[[registry]]` settings declared as
/// <https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md#namespaced-registry-settings>
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Registry {
    /// A prefix of the user-specified image name to be replaced
    /// Format like:
    /// - `host[:port]`
    /// - `host[:port]/namespace[/namespace…]`
    /// - `host[:port]/namespace[/namespace…]/repo`
    /// - `host[:port]/namespace[/namespace…]/repo(:_tag|@digest)`
    /// - `[*.]host`
    #[serde(default)]
    prefix: String,

    /// Whether unencrypted HTTP as well as TLS connections with untrusted certificates are allowed.
    #[serde(default)]
    insecure: bool,

    /// Whether the registry is blocked.
    #[serde(default)]
    blocked: bool,

    /// Accepts the same format as the prefix field, and specifies the physical
    /// location of the prefix-rooted namespace.
    #[serde(default)]
    location: String,

    /// image mirrors
    #[serde(default)]
    mirror: Vec<Mirror>,
    // TODO: add aliases
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default = "unqualified_search_registries_default")]
    #[serde(rename = "unqualified-search-registries")]
    unqualified_search_registries: Vec<String>,

    #[serde(default)]
    registry: Vec<Registry>,
    // TODO: add credential-helpers
    // TODO: add additional-layer-store-auth-helper
}

/// This default value allows us to automatically search for the
/// image from Dockerhub when we do not define the image repo.
fn unqualified_search_registries_default() -> Vec<String> {
    vec!["docker.io".to_string()]
}

impl Config {
    pub fn validate_and_tidy(&mut self) -> Result<()> {
        for registry in &mut self.registry {
            if registry.prefix.is_empty() {
                if registry.location.is_empty() {
                    bail!("illegal Registry Config: both location and prefix are empty");
                }
                registry.prefix = registry.location.clone();
            }

            if registry.prefix.starts_with("*.") && registry.location.is_empty() {
                bail!("illegal Registry Config: location is unset and prefix is with wildcard");
            }

            for mirror in &registry.mirror {
                if mirror.location.is_empty() {
                    bail!("illegal Registry Config: mirror location is empty");
                }
            }
        }

        Ok(())
    }
}

pub struct RegistryHandler {
    config: Config,
}

enum MatchResult {
    Matched { length: usize },
    Unmatched,
}

impl RegistryHandler {
    pub fn new(mut config: Config) -> Result<Self> {
        config.validate_and_tidy()?;
        Ok(Self { config })
    }

    pub fn from_vec(s: Vec<u8>) -> Result<Self> {
        let registry_configuration = String::from_utf8(s)?;
        let mut config: Config = toml::from_str(&registry_configuration)?;
        config.validate_and_tidy()?;
        Ok(Self { config })
    }

    fn generate_unqualified_search_tasks(&self, reference: &Reference) -> Vec<ImagePullTask> {
        let mut tasks = Vec::new();

        for registry in &self.config.unqualified_search_registries {
            if registry == "docker.io" {
                let task = ImagePullTask {
                    image_reference: reference.clone(),
                    use_http: false,
                    task_type: TaskType::UnqualifiedSearch,
                };
                tasks.push(task);
                continue;
            }

            let repository = match reference.repository().starts_with("library/") {
                true => reference.repository()["library/".len()..].to_string(),
                false => reference.repository().to_string(),
            };
            let image_reference = match reference.tag() {
                Some(tag) => Reference::with_tag(registry.clone(), repository, tag.to_string()),
                None => Reference::with_digest(
                    registry.clone(),
                    repository,
                    // This unwrap is safe as a reference must have a digest or a tag.
                    reference.digest().unwrap().to_string(),
                ),
            };

            let task = ImagePullTask {
                image_reference,
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            };
            tasks.push(task);
        }

        tasks
    }

    /// This function will try to match the reference with the prefix.
    /// Wildcards are only accepted at the beginning, so other formats
    /// like `example.*.com` will not work.
    fn match_reference_prefix(reference: &str, prefix: &str) -> MatchResult {
        if prefix.starts_with("*.") {
            let Some(mut pos) = reference.find(&prefix[1..]) else {
                return MatchResult::Unmatched;
            };

            if reference[..pos].contains("/") {
                return MatchResult::Unmatched;
            }

            pos += prefix[1..].len();
            if pos == reference.len() {
                return MatchResult::Matched { length: pos };
            }

            // The unwrap here is safe because pos < reference.len()
            match reference.chars().nth(pos).unwrap() {
                ':' | '/' | '@' => return MatchResult::Matched { length: pos },
                _ => return MatchResult::Unmatched,
            };
        }

        let Some(mut pos) = reference.find(prefix) else {
            return MatchResult::Unmatched;
        };

        pos += prefix.len();
        if pos == reference.len() {
            return MatchResult::Matched { length: pos };
        }
        // The unwrap here is safe because pos < reference.len()
        match reference.chars().nth(pos).unwrap() {
            ':' | '/' | '@' => MatchResult::Matched { length: pos },
            _ => MatchResult::Unmatched,
        }
    }

    fn handle_registry_tasks(
        &self,
        original_tasks: Vec<ImagePullTask>,
    ) -> Result<Vec<ImagePullTask>> {
        let mut tasks = Vec::new();

        // Note: This might cause some unexpected bug, as the rule defined in
        // <https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md#choosing-a-registry-toml-table>
        // One of or neither of tag and digest can exist. But the `to_string()` here
        // can generate string like `...:tag@digest` with both tag and digest.
        //
        // To totally resolve this, we need to define our own `Reference` parsing
        // logic and conversion logic.
        //
        // However, users usually do not include digest in the reference of the image,
        // so we explicitly ignore the case temporarily.
        //
        // To keep the first implementation simple enough, we leave a TODO for this.
        for task in original_tasks {
            let reference_string = task.image_reference.to_string();
            let matched_rule = self
                .config
                .registry
                .iter()
                .filter_map(|registry| {
                    match Self::match_reference_prefix(&reference_string, &registry.prefix) {
                        MatchResult::Matched { length } => Some((length, registry)),
                        MatchResult::Unmatched => None,
                    }
                })
                .max_by_key(|&(matched_len, _)| matched_len);

            // if no rules are found. Just pull the original task.
            let Some((matched_len, registry_rule)) = matched_rule else {
                let original_task = ImagePullTask {
                    image_reference: task.image_reference,
                    use_http: false,
                    task_type: task.task_type,
                };
                tasks.push(original_task);
                continue;
            };

            // check if the pulling is blocked
            if registry_rule.blocked {
                debug!("Image {reference_string} is blocked by registry rule.");
                continue;
            }

            // Firstly, Mirror tasks
            for mirror in &registry_rule.mirror {
                let mirrored_reference =
                    format!("{}{}", mirror.location, &reference_string[matched_len..]);
                let task = ImagePullTask {
                    image_reference: Reference::from_str(&mirrored_reference)?,
                    use_http: mirror.insecure,
                    task_type: TaskType::Mirror,
                };

                tasks.push(task);
            }

            // Then, Remapping task
            if !registry_rule.location.is_empty() {
                let remapping_reference = format!(
                    "{}{}",
                    registry_rule.location,
                    &reference_string[matched_len..]
                );

                let task_type = match registry_rule.location == "docker.io" {
                    true => task.task_type,
                    false => TaskType::Remapped,
                };
                let remapping_task = ImagePullTask {
                    image_reference: Reference::from_str(&remapping_reference)?,
                    use_http: registry_rule.insecure,
                    task_type,
                };
                tasks.push(remapping_task);
            }
            // If no remapping task, original task
            else {
                tasks.push(task);
            }
        }

        Ok(tasks)
    }

    /// Due to the [Remapping and mirroring registries](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md#remapping-and-mirroring-registries),
    /// `mirror` will let the client to try many different image
    /// sources, thus this function will return a list of image pull tasks for future
    /// use.
    pub fn process(&self, image_reference: Reference) -> Result<Vec<ImagePullTask>> {
        let mut tasks = Vec::new();

        // First, try all unqualified search registries
        //
        // The original rule is to add registries to handle an unqualified image.
        // Crate `oci-spec`'s parser logic of [`oci_client::Reference`] will automatically
        // add `docker.io` to unqualified images.
        // Thus this call will try to add tasks for image pull request whose registry
        // is `docker.io`.
        //
        // TODO: This is sometimes not a good idea, as the user might want to
        // pull images like `docker.io/foo/bar` directly but current implementation will add
        // tries from registries in `unqualified_search_registries` We can handle this later.
        if image_reference.registry() != "docker.io" {
            tasks.push(ImagePullTask {
                image_reference: image_reference.clone(),
                use_http: false,
                task_type: TaskType::Origininal,
            });
        } else {
            tasks = self.generate_unqualified_search_tasks(&image_reference);
        }

        // Then, use remapping and mirroring registries to handle
        let final_tasks = self.handle_registry_tasks(tasks)?;

        if final_tasks.is_empty() {
            bail!(
                "Image {} is blocked by registry rule.",
                image_reference.to_string()
            );
        }
        Ok(final_tasks)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oci_client::Reference;

    use crate::image::{ImagePullTask, TaskType};

    use super::RegistryHandler;

    fn registry_handler() -> RegistryHandler {
        let config = r#"
unqualified-search-registries = ["docker.io", "example1.com"]

[[registry]]
prefix = "example.com/banned"
blocked = true

[[registry]]
prefix = "example.com/foo"
insecure = false
blocked = false
location = "internal-registry-for-example.com/bar"

[[registry.mirror]]
location = "example-mirror-0.local/mirror-for-foo"

[[registry.mirror]]
location = "example-mirror-1.local/mirrors/foo"
insecure = true

[[registry]]
location = "docker.io"

[[registry.mirror]]
location = "123456.mirror.aliyuncs.com"
"#;

        RegistryHandler::from_vec(config.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn block_repository() {
        let registry_handler = registry_handler();
        let reference = "example.com/banned/image:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference);
        let err = result.unwrap_err();
        assert!(format!("{err:#?}").contains("is blocked by registry rule"));
    }

    #[test]
    fn no_block_registry_1() {
        let registry_handler = registry_handler();
        let reference = "example.com/no-banned/image:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference);
        assert!(result.is_ok());
    }

    #[test]
    fn no_block_registry_2() {
        let registry_handler = registry_handler();
        let reference = "example.com/banned-suffix/image:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference);
        assert!(result.is_ok());
    }

    #[test]
    fn unqualified_search_registries_1() {
        let registry_handler = registry_handler();
        let reference = "bar:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference).unwrap();
        let expected = vec![
            ImagePullTask {
                image_reference: Reference::from_str("123456.mirror.aliyuncs.com/library/bar:tag")
                    .unwrap(),
                use_http: false,
                task_type: TaskType::Mirror,
            },
            ImagePullTask {
                image_reference: Reference::from_str("docker.io/library/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
            ImagePullTask {
                image_reference: Reference::from_str("example1.com/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
        ];
        assert_eq!(expected, result);
    }

    #[test]
    fn unqualified_search_registries_2() {
        let registry_handler = registry_handler();
        let reference = "foo/bar:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference).unwrap();
        let expected = vec![
            ImagePullTask {
                image_reference: Reference::from_str("123456.mirror.aliyuncs.com/foo/bar:tag")
                    .unwrap(),
                use_http: false,
                task_type: TaskType::Mirror,
            },
            ImagePullTask {
                image_reference: Reference::from_str("docker.io/foo/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
            ImagePullTask {
                image_reference: Reference::from_str("example1.com/foo/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
        ];
        assert_eq!(expected, result);
    }

    #[test]
    fn registry_mirror_1() {
        let registry_handler = registry_handler();
        let reference = "example.com/foo/image:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference).unwrap();
        let expected = vec![
            ImagePullTask {
                image_reference: Reference::from_str(
                    "example-mirror-0.local/mirror-for-foo/image:tag",
                )
                .unwrap(),
                use_http: false,
                task_type: TaskType::Mirror,
            },
            ImagePullTask {
                image_reference: Reference::from_str(
                    "example-mirror-1.local/mirrors/foo/image:tag",
                )
                .unwrap(),
                use_http: true,
                task_type: TaskType::Mirror,
            },
            ImagePullTask {
                image_reference: Reference::from_str(
                    "internal-registry-for-example.com/bar/image:tag",
                )
                .unwrap(),
                use_http: false,
                task_type: TaskType::Remapped,
            },
        ];

        assert_eq!(expected, result);
    }

    #[test]
    fn registry_mirror_2() {
        let registry_handler = registry_handler();
        let reference = "bar:tag";
        let reference = Reference::from_str(reference).unwrap();
        let result = registry_handler.process(reference).unwrap();
        let expected = vec![
            ImagePullTask {
                image_reference: Reference::from_str("123456.mirror.aliyuncs.com/library/bar:tag")
                    .unwrap(),
                use_http: false,
                task_type: TaskType::Mirror,
            },
            ImagePullTask {
                image_reference: Reference::from_str("docker.io/library/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
            ImagePullTask {
                image_reference: Reference::from_str("example1.com/bar:tag").unwrap(),
                use_http: false,
                task_type: TaskType::UnqualifiedSearch,
            },
        ];
        assert_eq!(expected, result);
    }
}
