// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use oci_spec::image::{ImageConfiguration, Os};
use safe_path::PinnedPathBuf;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::config::ImageConfig;
use crate::decoder::Compression;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::snapshots::overlay::OverLay;
use crate::snapshots::{SnapshotType, Snapshotter};

/// The metadata info for container image layer.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LayerMeta {
    /// Image layer compression algorithm type.
    pub decoder: Compression,

    /// Whether image layer is encrypted.
    pub encrypted: bool,

    /// The compressed digest of image layer.
    pub compressed_digest: String,

    /// The uncompressed digest of image layer.
    pub uncompressed_digest: String,

    /// The image layer storage path.
    pub store_path: String,
}

/// The metadata info for container image.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ImageMeta {
    /// The digest of the image configuration.
    pub id: String,

    /// The digest of the image.
    pub digest: String,

    /// The reference string for the image
    pub reference: String,

    /// The image configuration.
    pub image_config: ImageConfiguration,

    /// Whether image is signed.
    pub signed: bool,

    /// The metadata of image layers.
    pub layer_metas: Vec<LayerMeta>,
}

/// The`image-rs` client will support OCI image
/// pulling, image signing verfication, image layer
/// decryption/unpack/store and management.
pub struct ImageClient {
    /// The config for `image-rs` client.
    pub config: ImageConfig,

    /// The metadata database for `image-rs` client.
    pub meta_store: Arc<Mutex<MetaStore>>,

    /// The supported snapshots for `image-rs` client.
    pub snapshots: HashMap<SnapshotType, Box<dyn Snapshotter>>,
}

impl Default for ImageClient {
    // construct a default instance of `ImageClient`
    fn default() -> ImageClient {
        let config = ImageConfig::default();
        let meta_store = MetaStore::try_from(Path::new(METAFILE)).unwrap_or_default();

        let mut snapshots = HashMap::new();

        let overlay_index = meta_store
            .snapshot_db
            .get(&SnapshotType::Overlay.to_string())
            .unwrap_or(&0);
        let overlay = OverLay {
            data_dir: config.work_dir.join(SnapshotType::Overlay.to_string()),
            index: AtomicUsize::new(*overlay_index),
        };

        snapshots.insert(
            SnapshotType::Overlay,
            Box::new(overlay) as Box<dyn Snapshotter>,
        );

        ImageClient {
            config,
            meta_store: Arc::new(Mutex::new(meta_store)),
            snapshots,
        }
    }
}

impl ImageClient {
    /// pull_image pulls an image with optional auth info and decrypt config
    /// and store the pulled data under user defined work_dir/layers.
    /// It will return the image ID with prepeared bundle: a rootfs directory,
    /// and config.json will be ready in the bundle_dir passed by user.
    pub async fn pull_image(
        &mut self,
        image_url: &str,
        bundle_dir: &PinnedPathBuf,
        auth_info: &Option<&str>,
        decrypt_config: &Option<&str>,
    ) -> Result<String> {
        let mut client =
            PullClient::new(image_url, &self.config.work_dir.join("layers"), auth_info)?;
        let (image_manifest, image_digest, image_config) = client.pull_manifest().await?;

        let id = image_manifest.config.digest.clone();
        if self.meta_store.lock().await.image_db.contains_key(&id) {
            return Ok(id);
        }

        // TODO Image Signature Verification.

        let mut image_data = ImageMeta {
            id,
            digest: image_digest,
            reference: image_url.to_string(),
            image_config: ImageConfiguration::from_reader(image_config.as_bytes())?,
            ..Default::default()
        };

        let diff_ids = image_data.image_config.rootfs().diff_ids();
        if diff_ids.len() != image_manifest.layers.len() {
            return Err(anyhow!(
                "Pulled number of layers mismatch with image config diff_ids"
            ));
        }

        let layer_metas = client
            .pull_layers(
                image_manifest.layers.clone(),
                diff_ids,
                decrypt_config,
                self.meta_store.clone(),
            )
            .await?;

        image_data.layer_metas = layer_metas;
        let layer_db: HashMap<String, LayerMeta> = image_data
            .layer_metas
            .iter()
            .map(|layer| (layer.compressed_digest.clone(), layer.clone()))
            .collect();

        self.meta_store.lock().await.layer_db.extend(layer_db);

        let layer_path = image_data
            .layer_metas
            .iter()
            .rev()
            .map(|l| l.store_path.as_str())
            .collect::<Vec<&str>>();

        if let Some(snapshot) = self.snapshots.get_mut(&self.config.default_snapshot) {
            snapshot.mount(&layer_path, &bundle_dir.join(BUNDLE_ROOTFS))?;
        } else {
            return Err(anyhow!(
                "default snapshot {} not found",
                &self.config.default_snapshot
            ));
        }

        let image_config = image_data.image_config.clone();
        if image_config.os() != &Os::Linux {
            return Err(anyhow!("unsupport OS image {:?}", image_config.os()));
        }

        create_runtime_config(&image_config, bundle_dir)?;
        let image_id = image_data.id.clone();
        self.meta_store
            .lock()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data);

        Ok(image_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pull_image() {
        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());

        // TODO test with more OCI image registries and fix broken registries.
        let oci_images = vec![
            // Alibaba Container Registry
            "registry.cn-hangzhou.aliyuncs.com/acs/busybox:v1.29.2",
            // Amazon Elastic Container Registry
            // "public.ecr.aws/docker/library/hello-world:linux"

            // Azure Container Registry
            "mcr.microsoft.com/hello-world",
            // Docker container Registry
            "docker.io/i386/busybox",
            // Google Container Registry
            "gcr.io/google-containers/busybox:1.27.2",
            // JFrog Container Registry
            // "releases-docker.jfrog.io/reg2/busybox:1.33.1"
        ];

        let mut image_client = ImageClient::default();
        for image in oci_images.iter() {
            let tempdir = tempfile::tempdir().unwrap();
            let temp_path = tempdir.path().canonicalize().unwrap();
            let bundle_dir = PinnedPathBuf::from_path(temp_path).unwrap();

            assert!(image_client
                .pull_image(image, &bundle_dir, &None, &None)
                .await
                .is_ok());
        }

        assert_eq!(image_client.meta_store.lock().await.image_db.len(), 4);
    }
}
