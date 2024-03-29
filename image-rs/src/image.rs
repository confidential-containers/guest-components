// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use log::warn;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use oci_spec::image::{ImageConfiguration, Os};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::config::{ImageConfig, CONFIGURATION_FILE_PATH};
use crate::decoder::Compression;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::snapshots::{SnapshotType, Snapshotter};

#[cfg(feature = "snapshot-unionfs")]
use crate::snapshots::occlum::unionfs::Unionfs;
#[cfg(feature = "snapshot-overlayfs")]
use crate::snapshots::overlay::OverlayFs;

#[cfg(feature = "nydus")]
use crate::nydus::{service, utils};

/// Image security config dir contains important information such as
/// security policy configuration file and signature verification configuration file.
/// Therefore, it is necessary to ensure that the directory is stored in a safe place.
///
/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
pub const IMAGE_SECURITY_CONFIG_DIR: &str = "/run/image-security";

/// The metadata info for container image layer.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
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
        let config = ImageConfig::try_from(Path::new(CONFIGURATION_FILE_PATH)).unwrap_or_default();
        let meta_store = MetaStore::try_from(Path::new(METAFILE)).unwrap_or_default();
        let snapshots = Self::init_snapshots(&config, &meta_store);

        ImageClient {
            config,
            meta_store: Arc::new(Mutex::new(meta_store)),
            snapshots,
        }
    }
}

impl ImageClient {
    ///Initialize metadata database and supported snapshots.
    pub fn init_snapshots(
        config: &ImageConfig,
        meta_store: &MetaStore,
    ) -> HashMap<SnapshotType, Box<dyn Snapshotter>> {
        let mut snapshots = HashMap::new();

        #[cfg(feature = "snapshot-overlayfs")]
        {
            let overlay_index = meta_store
                .snapshot_db
                .get(&SnapshotType::Overlay.to_string())
                .unwrap_or(&0);
            let data_dir = config.work_dir.join(SnapshotType::Overlay.to_string());
            let overlayfs = OverlayFs::new(
                data_dir,
                std::sync::atomic::AtomicUsize::new(*overlay_index),
            );
            snapshots.insert(
                SnapshotType::Overlay,
                Box::new(overlayfs) as Box<dyn Snapshotter>,
            );
        }
        #[cfg(feature = "snapshot-unionfs")]
        {
            let occlum_unionfs_index = meta_store
                .snapshot_db
                .get(&SnapshotType::OcclumUnionfs.to_string())
                .unwrap_or(&0);
            let occlum_unionfs = Unionfs {
                data_dir: config
                    .work_dir
                    .join(SnapshotType::OcclumUnionfs.to_string()),
                index: std::sync::atomic::AtomicUsize::new(*occlum_unionfs_index),
            };
            snapshots.insert(
                SnapshotType::OcclumUnionfs,
                Box::new(occlum_unionfs) as Box<dyn Snapshotter>,
            );
        }
        snapshots
    }

    /// Create an ImageClient instance with specific work directory.
    pub fn new(image_work_dir: PathBuf) -> Self {
        let config = ImageConfig::new(image_work_dir);
        let meta_store = MetaStore::try_from(Path::new(METAFILE)).unwrap_or_default();
        let snapshots = Self::init_snapshots(&config, &meta_store);

        Self {
            config,
            meta_store: Arc::new(Mutex::new(meta_store)),
            snapshots,
        }
    }

    /// pull_image pulls an image with optional auth info and decrypt config
    /// and store the pulled data under user defined work_dir/layers.
    /// It will return the image ID with prepeared bundle: a rootfs directory,
    /// and config.json will be ready in the bundle_dir passed by user.
    ///
    /// If at least one of `security_validate` and `auth` in self.config is
    /// enabled, `auth_info` **must** be given. There will establish a SecureChannel
    /// due to the given `decrypt_config` which contains information about
    /// `wrapped_aa_kbc_params`.
    /// When `auth_info` parameter is given and `auth` in self.config is also enabled,
    /// this function will only try to get auth from `auth_info`, and if fails then
    /// then returns an error.
    pub async fn pull_image(
        &mut self,
        image_url: &str,
        bundle_dir: &Path,
        auth_info: &Option<&str>,
        decrypt_config: &Option<&str>,
    ) -> Result<String> {
        let reference = Reference::try_from(image_url)?;

        // Try to get auth using input param.
        let auth = if let Some(auth_info) = auth_info {
            if let Some((username, password)) = auth_info.split_once(':') {
                let auth = RegistryAuth::Basic(username.to_string(), password.to_string());
                Some(auth)
            } else {
                bail!("Invalid authentication info ({:?})", auth_info);
            }
        } else {
            None
        };

        // If one of self.config.auth and self.config.security_validate is enabled,
        // there will establish a secure channel
        #[cfg(feature = "getresource")]
        if self.config.auth || self.config.security_validate {
            // Both we need a [`IMAGE_SECURITY_CONFIG_DIR`] dir
            if !Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
                tokio::fs::create_dir_all(IMAGE_SECURITY_CONFIG_DIR)
                    .await
                    .map_err(|e| {
                        anyhow!("Create image security runtime config dir failed: {:?}", e)
                    })?;
            }

            let mut channel = crate::resource::SECURE_CHANNEL.lock().await;
            *channel = Some(crate::resource::kbs::SecureChannel::new(decrypt_config).await?);
        };

        // If no valid auth is given and config.auth is enabled, try to load
        // auth from `auth.json` of given place.
        // If a proper auth is given, use this auth.
        // If no valid auth is given and config.auth is disabled, use Anonymous auth.
        let auth = match (self.config.auth, auth.is_none()) {
            (true, true) => {
                match crate::auth::credential_for_reference(
                    &reference,
                    &self.config.file_paths.auth_file,
                )
                .await
                {
                    Ok(cred) => cred,
                    Err(e) => {
                        warn!(
                            "get credential failed, use Anonymous auth instead: {}",
                            e.to_string()
                        );
                        RegistryAuth::Anonymous
                    }
                }
            }
            (false, true) => RegistryAuth::Anonymous,
            _ => auth.expect("unexpected uninitialized auth"),
        };

        let mut client = PullClient::new(
            reference,
            &self.config.work_dir.join("layers"),
            &auth,
            self.config.max_concurrent_download,
        )?;
        let (image_manifest, image_digest, image_config) = client.pull_manifest().await?;

        let id = image_manifest.config.digest.clone();

        let snapshot = match self.snapshots.get_mut(&self.config.default_snapshot) {
            Some(s) => s,
            _ => {
                bail!(
                    "default snapshot {} not found",
                    &self.config.default_snapshot
                );
            }
        };

        #[cfg(feature = "nydus")]
        if utils::is_nydus_image(&image_manifest) {
            {
                let m = self.meta_store.lock().await;
                if let Some(image_data) = &m.image_db.get(&id) {
                    return service::create_nydus_bundle(image_data, bundle_dir, snapshot);
                }
            }

            #[cfg(feature = "signature")]
            if self.config.security_validate {
                crate::signature::allows_image(
                    image_url,
                    &image_digest,
                    &auth,
                    &self.config.file_paths,
                )
                .await
                .map_err(|e| anyhow!("Security validate failed: {:?}", e))?;
            }

            let (mut image_data, _, _) = create_image_meta(
                &id,
                image_url,
                &image_manifest,
                &image_digest,
                &image_config,
            )?;

            return self
                .do_pull_image_with_nydus(
                    &mut client,
                    &mut image_data,
                    &image_manifest,
                    decrypt_config,
                    bundle_dir,
                )
                .await;
        }

        // If image has already been populated, just create the bundle.
        {
            let m = self.meta_store.lock().await;
            if let Some(image_data) = &m.image_db.get(&id) {
                return create_bundle(image_data, bundle_dir, snapshot);
            }
        }

        #[cfg(feature = "signature")]
        if self.config.security_validate {
            crate::signature::allows_image(
                image_url,
                &image_digest,
                &auth,
                &self.config.file_paths,
            )
            .await
            .map_err(|e| anyhow!("Security validate failed: {:?}", e))?;
        }

        let (mut image_data, unique_layers, unique_diff_ids) = create_image_meta(
            &id,
            image_url,
            &image_manifest,
            &image_digest,
            &image_config,
        )?;

        let unique_layers_len = unique_layers.len();
        let layer_metas = client
            .async_pull_layers(
                unique_layers,
                &unique_diff_ids,
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
        if unique_layers_len != image_data.layer_metas.len() {
            bail!(
                " {} layers failed to pull",
                unique_layers_len - image_data.layer_metas.len()
            );
        }

        let image_id = create_bundle(&image_data, bundle_dir, snapshot)?;

        self.meta_store
            .lock()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data.clone());

        Ok(image_id)
    }

    #[cfg(feature = "nydus")]
    async fn do_pull_image_with_nydus<'a>(
        &mut self,
        client: &mut PullClient<'_>,
        image_data: &mut ImageMeta,
        image_manifest: &OciImageManifest,
        decrypt_config: &Option<&str>,
        bundle_dir: &Path,
    ) -> Result<String> {
        let diff_ids = image_data.image_config.rootfs().diff_ids();
        let bootstrap_id = if !diff_ids.is_empty() {
            diff_ids[diff_ids.len() - 1].to_string()
        } else {
            bail!("Failed to get bootstrap id, diff_ids is empty");
        };

        let bootstrap = utils::get_nydus_bootstrap_desc(image_manifest)
            .ok_or_else(|| anyhow!("Faild to get bootstrap oci descriptor"))?;
        let layer_metas = client
            .pull_bootstrap(
                bootstrap,
                bootstrap_id.to_string(),
                decrypt_config,
                self.meta_store.clone(),
            )
            .await?;
        image_data.layer_metas = vec![layer_metas];
        let layer_db: HashMap<String, LayerMeta> = image_data
            .layer_metas
            .iter()
            .map(|layer| (layer.compressed_digest.clone(), layer.clone()))
            .collect();

        self.meta_store.lock().await.layer_db.extend(layer_db);

        if image_data.layer_metas.is_empty() {
            bail!("Failed to pull the bootstrap");
        }

        let reference = Reference::try_from(image_data.reference.clone())?;
        let nydus_config = self
            .config
            .get_nydus_config()
            .expect("Nydus configuration not found");
        let work_dir = self.config.work_dir.clone();
        let snapshot = match self.snapshots.get_mut(&self.config.default_snapshot) {
            Some(s) => s,
            _ => {
                bail!(
                    "default snapshot {} not found",
                    &self.config.default_snapshot
                );
            }
        };
        let image_id = service::start_nydus_service(
            image_data,
            reference,
            nydus_config,
            &work_dir,
            bundle_dir,
            snapshot,
        )
        .await?;

        self.meta_store
            .lock()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data.clone());

        Ok(image_id)
    }
}

/// Create image meta object with the image info
/// Return the image meta object, oci descriptors of the unique layers, and unique diff ids.
fn create_image_meta(
    id: &str,
    image_url: &str,
    image_manifest: &OciImageManifest,
    image_digest: &str,
    image_config: &str,
) -> Result<(ImageMeta, Vec<OciDescriptor>, Vec<String>)> {
    let image_data = ImageMeta {
        id: id.to_string(),
        digest: image_digest.to_string(),
        reference: image_url.to_string(),
        image_config: ImageConfiguration::from_reader(image_config.to_string().as_bytes())?,
        ..Default::default()
    };

    let diff_ids = image_data.image_config.rootfs().diff_ids();
    if diff_ids.len() != image_manifest.layers.len() {
        bail!("Pulled number of layers mismatch with image config diff_ids");
    }

    let mut unique_layers = Vec::new();
    let mut digests = BTreeSet::new();
    for l in &image_manifest.layers {
        if digests.contains(&l.digest) {
            continue;
        }

        digests.insert(&l.digest);
        unique_layers.push(l.clone());
    }

    let mut unique_diff_ids = Vec::new();
    let mut id_tree = BTreeSet::new();
    for id in diff_ids {
        if id_tree.contains(id.as_str()) {
            continue;
        }

        id_tree.insert(id.as_str());
        unique_diff_ids.push(id.clone());
    }

    Ok((image_data, unique_layers, unique_diff_ids))
}

fn create_bundle(
    image_data: &ImageMeta,
    bundle_dir: &Path,
    snapshot: &mut Box<dyn Snapshotter>,
) -> Result<String> {
    let layer_path = image_data
        .layer_metas
        .iter()
        .rev()
        .map(|l| l.store_path.as_str())
        .collect::<Vec<&str>>();

    snapshot.mount(&layer_path, &bundle_dir.join(BUNDLE_ROOTFS))?;

    let image_config = image_data.image_config.clone();
    if image_config.os() != &Os::Linux {
        bail!("unsupport OS image {:?}", image_config.os());
    }

    create_runtime_config(&image_config, bundle_dir)?;
    let image_id = image_data.id.clone();
    Ok(image_id)
}

#[cfg(feature = "snapshot-overlayfs")]
#[cfg(test)]
mod tests {
    use super::*;

    use test_utils::assert_retry;

    #[tokio::test]
    async fn test_pull_image() {
        let work_dir = tempfile::tempdir().unwrap();

        // TODO test with more OCI image registries and fix broken registries.
        let oci_images = [
            // image with duplicated layers
            "gcr.io/k8s-staging-cloud-provider-ibm/ibm-vpc-block-csi-driver:master",
            // Alibaba Container Registry
            "registry.cn-hangzhou.aliyuncs.com/acs/busybox:v1.29.2",
            // Amazon Elastic Container Registry
            // "public.ecr.aws/docker/library/hello-world:linux"

            // Azure Container Registry
            "mcr.microsoft.com/hello-world",
            // Docker container Registry
            "docker.io/busybox",
            // Google Container Registry
            "gcr.io/google-containers/busybox:1.27.2",
            // JFrog Container Registry
            // "releases-docker.jfrog.io/reg2/busybox:1.33.1"
        ];

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());
        for image in oci_images.iter() {
            let bundle_dir = tempfile::tempdir().unwrap();

            assert_retry!(
                5,
                1,
                image_client,
                pull_image,
                image,
                bundle_dir.path(),
                &None,
                &None
            );
        }

        assert_eq!(
            image_client.meta_store.lock().await.image_db.len(),
            oci_images.len()
        );
    }

    #[cfg(feature = "nydus")]
    #[tokio::test]
    async fn test_nydus_image() {
        let work_dir = tempfile::tempdir().unwrap();

        let nydus_images = [
            "eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/v6/java:latest-test_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/ubuntu:latest_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/python:latest_nydus",
        ];

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        for image in nydus_images.iter() {
            let bundle_dir = tempfile::tempdir().unwrap();

            assert_retry!(
                5,
                1,
                image_client,
                pull_image,
                image,
                bundle_dir.path(),
                &None,
                &None
            );
        }

        assert_eq!(
            image_client.meta_store.lock().await.image_db.len(),
            nydus_images.len()
        );
    }

    #[tokio::test]
    async fn test_image_reuse() {
        let work_dir = tempfile::tempdir().unwrap();

        let image = "mcr.microsoft.com/hello-world";

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        let bundle1_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle1_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Pull image again.
        let bundle2_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle2_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Assert that config is written out.
        assert!(bundle1_dir.path().join("config.json").exists());
        assert!(bundle2_dir.path().join("config.json").exists());

        // Assert that rootfs is populated.
        assert!(bundle1_dir.path().join("rootfs").join("hello").exists());
        assert!(bundle2_dir.path().join("rootfs").join("hello").exists());

        // Assert that image is pulled only once.
        assert_eq!(image_client.meta_store.lock().await.image_db.len(), 1);
    }
}
