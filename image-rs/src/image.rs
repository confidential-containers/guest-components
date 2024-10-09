// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use log::info;
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use oci_spec::image::{ImageConfiguration, Os};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::auth::Auth;
use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::config::{ImageConfig, CONFIGURATION_FILE_NAME, DEFAULT_WORK_DIR};
use crate::decoder::Compression;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::signature::SignatureValidator;
use crate::snapshots::{SnapshotType, Snapshotter};

#[cfg(feature = "snapshot-unionfs")]
use crate::snapshots::occlum::unionfs::Unionfs;
#[cfg(feature = "snapshot-overlayfs")]
use crate::snapshots::overlay::OverlayFs;

#[cfg(feature = "nydus")]
use crate::nydus::{service, utils};

/// The metadata info for container image layer.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    /// The registry auths to authenticate to private registries
    pub(crate) registry_auth: Option<Auth>,

    /// The image pull security module
    /// it is used to filter image pull requests against a
    /// policy
    pub(crate) signature_validator: Option<SignatureValidator>,

    /// The metadata database for `image-rs` client.
    pub(crate) meta_store: Arc<RwLock<MetaStore>>,

    /// The supported snapshots for `image-rs` client.
    pub(crate) snapshots: HashMap<SnapshotType, Box<dyn Snapshotter>>,

    /// The config
    pub(crate) config: ImageConfig,
}

impl Default for ImageClient {
    // construct a default instance of `ImageClient`
    fn default() -> ImageClient {
        let work_dir = Path::new(DEFAULT_WORK_DIR);
        let config = ImageConfig::try_from(work_dir.join(CONFIGURATION_FILE_NAME).as_path())
            .unwrap_or_default();
        let meta_store = MetaStore::try_from(work_dir.join(METAFILE).as_path()).unwrap_or_default();
        let snapshots = Self::init_snapshots(&config.work_dir, &meta_store);
        ImageClient {
            registry_auth: None,
            meta_store: Arc::new(RwLock::new(meta_store)),
            snapshots,
            signature_validator: None,
            config,
        }
    }
}

impl ImageClient {
    ///Initialize metadata database and supported snapshots.
    pub fn init_snapshots(
        work_dir: &Path,
        _meta_store: &MetaStore,
    ) -> HashMap<SnapshotType, Box<dyn Snapshotter>> {
        let mut snapshots = HashMap::new();

        #[cfg(feature = "snapshot-overlayfs")]
        {
            let data_dir = work_dir.join(SnapshotType::Overlay.to_string());
            let overlayfs = OverlayFs::new(data_dir);
            snapshots.insert(
                SnapshotType::Overlay,
                Box::new(overlayfs) as Box<dyn Snapshotter>,
            );
        }
        #[cfg(feature = "snapshot-unionfs")]
        {
            let occlum_unionfs_index = _meta_store
                .snapshot_db
                .get(&SnapshotType::OcclumUnionfs.to_string())
                .unwrap_or(&0);
            let occlum_unionfs = Unionfs {
                data_dir: work_dir.join(SnapshotType::OcclumUnionfs.to_string()),
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
    pub fn new(work_dir: PathBuf) -> Self {
        let config = ImageConfig::try_from(work_dir.join(CONFIGURATION_FILE_NAME).as_path())
            .unwrap_or_else(|_| ImageConfig::new(work_dir.clone()));
        let meta_store = MetaStore::try_from(work_dir.join(METAFILE).as_path()).unwrap_or_default();
        let snapshots = Self::init_snapshots(&config.work_dir, &meta_store);

        Self {
            meta_store: Arc::new(RwLock::new(meta_store)),
            snapshots,
            registry_auth: None,
            signature_validator: None,
            config,
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

        // Try to find a valid registry auth. Logic order
        // 1. the input parameter
        // 2. from self.registry_auth
        // 3. use Anonymous auth
        let auth = match auth_info {
            Some(input_auth) => match input_auth.split_once(':') {
                Some((username, password)) => {
                    RegistryAuth::Basic(username.to_string(), password.to_string())
                }
                None => bail!("Invalid authentication info ({:?})", auth_info),
            },
            None => match &self.registry_auth {
                Some(registry_auth) => registry_auth.credential_for_reference(&reference).await?,
                None => {
                    info!("Use Anonymous image registry auth");
                    RegistryAuth::Anonymous
                }
            },
        };

        let mut client = PullClient::new(
            reference,
            &self.config.work_dir.join("layers"),
            &auth,
            self.config.max_concurrent_layer_downloads_per_image,
            self.config.skip_proxy_ips.as_deref(),
            self.config.image_pull_proxy.as_deref(),
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
                let m = self.meta_store.read().await;
                if let Some(image_data) = &m.image_db.get(&id) {
                    return service::create_nydus_bundle(image_data, bundle_dir, snapshot);
                }
            }

            #[cfg(feature = "signature")]
            if let Some(signature_validator) = &self.signature_validator {
                signature_validator
                    .check_image_signature(image_url, &image_digest, &auth)
                    .await
                    .context("image security validation failed")?;
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
            let m = self.meta_store.read().await;
            if let Some(image_data) = &m.image_db.get(&id) {
                return create_bundle(image_data, bundle_dir, snapshot);
            }
        }

        #[cfg(feature = "signature")]
        if let Some(signature_validator) = &self.signature_validator {
            signature_validator
                .check_image_signature(image_url, &image_digest, &auth)
                .await
                .context("image security validation failed")?;
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

        self.meta_store.write().await.layer_db.extend(layer_db);
        if unique_layers_len != image_data.layer_metas.len() {
            bail!(
                " {} layers failed to pull",
                unique_layers_len - image_data.layer_metas.len()
            );
        }

        let image_id = create_bundle(&image_data, bundle_dir, snapshot)?;

        self.meta_store
            .write()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data.clone());

        let meta_file = self
            .config
            .work_dir
            .join(METAFILE)
            .to_string_lossy()
            .to_string();
        self.meta_store
            .write()
            .await
            .write_to_file(&meta_file)
            .context("update meta store failed")?;
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
            .ok_or_else(|| anyhow::anyhow!("Faild to get bootstrap oci descriptor"))?;
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

        self.meta_store.write().await.layer_db.extend(layer_db);

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
            .write()
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

#[cfg(not(target_arch = "s390x"))]
#[cfg(feature = "snapshot-overlayfs")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
            image_client.meta_store.read().await.image_db.len(),
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
            image_client.meta_store.read().await.image_db.len(),
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
        assert_eq!(image_client.meta_store.read().await.image_db.len(), 1);
    }

    #[tokio::test]
    async fn test_meta_store_reuse() {
        let work_dir = tempfile::tempdir().unwrap();

        let image = "mcr.microsoft.com/hello-world";

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        let bundle_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Create a second temporary directory for the second image client
        let work_dir_2 = tempfile::tempdir().unwrap();
        fs::create_dir_all(work_dir_2.path()).unwrap();

        // Lock the meta store and write its data to a file in the second work directory
        // This allows the second image client to reuse the meta store and layers from the first image client
        let store = image_client.meta_store.read().await;
        let meta_store_path = work_dir_2.path().to_str().unwrap().to_owned() + "/meta_store.json";
        store.write_to_file(&meta_store_path).unwrap();

        // Initialize the second image client with the second temporary directory
        let mut image_client_2 = ImageClient::new(work_dir_2.path().to_path_buf());

        let bundle_dir_2 = tempfile::tempdir().unwrap();
        if let Err(e) = image_client_2
            .pull_image(image, bundle_dir_2.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Verify that the "layers" directory does not exist in the second work directory
        // This confirms that the second image client reused the meta store and layers from the first image client
        assert!(!work_dir_2.path().join("layers").exists());
    }
}
