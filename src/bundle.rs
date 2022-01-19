// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use oci_spec::image::ImageConfiguration;
use oci_spec::runtime::{Mount, Process, Spec};

pub const BUNDLE_CONFIG: &str = "config.json";
pub const BUNDLE_ROOTFS: &str = "rootfs";
pub const BUNDLE_HOSTNAME: &str = "image-rs";

const ANNOTATION_OS: &str = "org.opencontainers.image.os";
const ANNOTATION_ARCH: &str = "org.opencontainers.image.architecture";
const ANNOTATION_AUTHOR: &str = "org.opencontainers.image.author";
const ANNOTATION_CREATED: &str = "org.opencontainers.image.created";
const ANNOTATION_STOP_SIGNAL: &str = "org.opencontainers.image.stopSignal";
const ANNOTATION_EXPOSED_PORTS: &str = "org.opencontainers.image.exposedPorts";

/// create_runtime_config will create the config.json file under the bundle_path,
/// and return the final bundle config path.
pub fn create_runtime_config(
    image_config: &ImageConfiguration,
    bundle_path: &Path,
) -> Result<PathBuf> {
    let mut spec = Spec::default();

    spec.set_hostname(Some(BUNDLE_HOSTNAME.to_string()));
    let mut annotations: HashMap<String, String> = HashMap::new();
    annotations.insert(ANNOTATION_OS.to_string(), image_config.os().to_string());
    annotations.insert(
        ANNOTATION_ARCH.to_string(),
        image_config.architecture().to_string(),
    );
    if let Some(author) = image_config.author() {
        annotations.insert(ANNOTATION_AUTHOR.to_string(), author.to_string());
    }
    if let Some(created) = image_config.created() {
        annotations.insert(ANNOTATION_CREATED.to_string(), created.to_string());
    }
    let mut process = Process::default();

    if let Some(config) = image_config.config() {
        if let Some(working_dir) = config.working_dir() {
            process.set_cwd(PathBuf::from(working_dir));
        }

        if let Some(env) = config.env() {
            process.set_env(Some(env.to_vec()));
        }

        let mut args: Vec<String> = vec![];
        if let Some(entrypoint) = config.entrypoint() {
            args.extend(entrypoint.clone());
        }

        if let Some(cmd) = config.cmd() {
            args.extend(cmd.clone());
        }

        if !args.is_empty() {
            process.set_args(Some(args));
        }

        if let Some(labels) = config.labels() {
            annotations.extend(labels.clone());
        }

        // TODO: parse image config user info and extract uid from rootfs passwd file
        // github issue: https://github.com/confidential-containers/image-rs/issues/8

        let mut mounts: Vec<Mount> = vec![];
        if let Some(volumes) = config.volumes() {
            for v in volumes.iter() {
                let mut m = Mount::default();
                m.set_destination(PathBuf::from(v))
                    .set_typ("tmpfs".to_string().into())
                    .set_source(None)
                    .set_options(Some(vec![
                        "nosuid".into(),
                        "noexec".into(),
                        "nodev".into(),
                        "relatime".into(),
                        "rw".into(),
                    ]));
                mounts.push(m.clone());
            }
        }

        if !mounts.is_empty() {
            if let Some(default_mounts) = spec.mounts() {
                mounts.extend(default_mounts.clone());
            }
            spec.set_mounts(Some(mounts));
        }

        if let Some(stop_signal) = config.stop_signal() {
            annotations.insert(ANNOTATION_STOP_SIGNAL.to_string(), stop_signal.to_string());
        }
        if let Some(exposed_ports) = config.exposed_ports() {
            annotations.insert(
                ANNOTATION_EXPOSED_PORTS.to_string(),
                exposed_ports.join(","),
            );
        }
    }

    spec.set_annotations(Some(annotations));
    let bundle_config = bundle_path.join(BUNDLE_CONFIG);
    spec.save(&bundle_config)?;

    Ok(bundle_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_bundle_create_config() {
        let image_config = ImageConfiguration::default();

        let tempdir = tempfile::tempdir().unwrap();
        let filename = tempdir.path().join(BUNDLE_CONFIG);

        assert!(!filename.exists());

        assert!(create_runtime_config(&image_config, tempdir.path()).is_ok());
        assert!(filename.exists());
    }
}
