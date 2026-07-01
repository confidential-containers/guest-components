// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use image_rs::config::ImageConfig;
use image_rs::registry::{Config as RegistryConfig, Registry};
use std::path::{Path, PathBuf};
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};
use tokio::process::Command;

pub fn conformance_images_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data/conformance-images")
}

pub fn image_config_for_registry(work_dir: PathBuf, registry_url: &str) -> ImageConfig {
    ImageConfig {
        work_dir,
        registry_config: Some(RegistryConfig {
            unqualified_search_registries: vec![],
            registry: vec![Registry {
                location: registry_url.to_string(),
                insecure: true,
                prefix: String::new(),
                blocked: false,
                mirror: vec![],
            }],
        }),
        ..Default::default()
    }
}

pub struct LocalRegistry {
    _container: ContainerAsync<GenericImage>,
    port: u16,
}

impl LocalRegistry {
    pub async fn start(port: u16) -> Result<Self> {
        let container = GenericImage::new("registry", "2")
            .with_wait_for(WaitFor::message_on_stderr("listening on [::]:5000"))
            .with_mapped_port(port, 5000.tcp())
            .start()
            .await
            .context("Failed to start registry container")?;

        Ok(Self {
            _container: container,
            port,
        })
    }

    pub fn url(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn image_ref(&self, name: &str) -> String {
        format!("{}/{}:latest", self.url(), name)
    }

    pub async fn load_image(&self, tar_path: &Path) -> Result<String> {
        let name = tar_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid tar filename"))?;

        let dest_ref = self.image_ref(name);

        let output = Command::new("skopeo")
            .args([
                "copy",
                &format!("oci-archive:{}", tar_path.display()),
                &format!("docker://{}", dest_ref),
                "--dest-tls-verify=false",
            ])
            .output()
            .await
            .context("Failed to execute skopeo")?;

        if !output.status.success() {
            bail!(
                "skopeo copy failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(dest_ref)
    }
}
