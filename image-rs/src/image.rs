// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context};
use log::{debug, error, info, warn};
use oci_client::{
    client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol},
    manifest::{OciDescriptor, OciImageManifest},
    secrets::RegistryAuth,
    ParseError, Reference,
};
use oci_spec::image::{ImageConfiguration, Os};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

use tokio::sync::RwLock;

use crate::decoder::Compression;
use crate::layer_store::LayerStore;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::signature::SignatureValidator;
use crate::snapshots::{SnapshotType, Snapshotter};
use crate::{auth::Auth, registry::RegistryHandler};
use crate::{
    bundle::{create_runtime_config, BUNDLE_ROOTFS},
    pull::PullLayerError,
};
use crate::{
    config::{ImageConfig, CONFIGURATION_FILE_NAME, DEFAULT_WORK_DIR},
    signature::SignatureError,
};

use crate::snapshots::overlay::OverlayFs;

pub type PullImageResult<T> = std::result::Result<T, PullImageError>;

#[derive(Error, Debug)]
pub enum PullImageError {
    #[error("Illegal image reference")]
    IllegalImageReference {
        #[source]
        source: ParseError,
    },

    #[error("failed to compose a legal image reference with given registry configuration")]
    IllegalRegistryConfigurationFormat {
        #[source]
        source: anyhow::Error,
    },

    #[error(
        "Failed to pull image {original_image_url} from all mirror/mapping locations or original location: {tried_list}"
    )]
    AllTasksTried {
        original_image_url: String,
        tried_list: String,
    },

    #[error("Illegal registry auth for image {image} from {auth_source}")]
    IllegalRegistryAuth { image: String, auth_source: String },

    #[error("Failed to pull image manifest")]
    FailedToPullManifest {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to create bundle")]
    FailedToCreateBundle {
        #[source]
        source: anyhow::Error,
    },

    #[cfg(feature = "signature")]
    #[error("Image policy rejected: {0}")]
    SignatureValidationFailed(#[from] SignatureError),

    #[error("{0} layers are not pulled successfully")]
    NotAllUniqueLayersPulled(usize),

    #[error("Errors happened when pulling image: {0}")]
    PullLayersFailed(#[from] PullLayerError),

    #[error("Internal error")]
    Internal {
        #[source]
        source: anyhow::Error,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskType {
    Origininal,
    Remapped,
    Mirror,
    UnqualifiedSearch,
}

/// A single image pull task
#[derive(Debug, Clone, PartialEq)]
pub struct ImagePullTask {
    pub image_reference: Reference,
    pub use_http: bool,
    pub task_type: TaskType,
}

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

/// The information of the pulled image.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageInfo {
    /// The digest of the image configuration.
    ///
    /// See `config` of <https://github.com/opencontainers/image-spec/blob/main/manifest.md>
    ///
    /// Usually in form `sha256:xxxxxx`
    pub config_digest: String,

    /// The digest of the [image manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
    ///
    /// Usually in form `sha256:xxxxxx`
    pub manifest_digest: String,
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

    /// Registry configuration module
    pub(crate) registry_handler: Option<RegistryHandler>,

    /// The metadata database for `image-rs` client.
    pub(crate) meta_store: Arc<RwLock<MetaStore>>,

    /// The supported snapshot for `image-rs` client.
    pub(crate) snapshot: Box<dyn Snapshotter>,

    /// The config
    pub(crate) config: ImageConfig,

    /// The image layer store
    pub(crate) layer_store: LayerStore,
}

impl Default for ImageClient {
    // construct a default instance of `ImageClient`
    fn default() -> ImageClient {
        let work_dir = Path::new(DEFAULT_WORK_DIR);
        ImageClient::new(work_dir.to_path_buf())
    }
}

impl ImageClient {
    ///Initialize metadata database and supported snapshots.
    pub fn init_snapshot(
        snapshot: &SnapshotType,
        work_dir: &Path,
        _meta_store: &MetaStore,
    ) -> Box<dyn Snapshotter> {
        match snapshot {
            SnapshotType::Overlay => {
                Box::new(OverlayFs::new(work_dir.to_path_buf())) as Box<dyn Snapshotter>
            }
        }
    }

    /// Create an ImageClient instance with specific work directory.
    pub fn new(work_dir: PathBuf) -> Self {
        let config = ImageConfig::try_from(work_dir.join(CONFIGURATION_FILE_NAME).as_path())
            .unwrap_or_else(|_| ImageConfig::new(work_dir.clone()));
        let meta_store = MetaStore::try_from(work_dir.join(METAFILE).as_path()).unwrap_or_default();
        let layer_store = LayerStore::new(work_dir).unwrap_or_else(|e| {
            error!("failed to construct layer store: {e:?}");
            LayerStore::default()
        });
        let snapshot = Self::init_snapshot(&config.default_snapshot, &config.work_dir, &meta_store);

        Self {
            meta_store: Arc::new(RwLock::new(meta_store)),
            snapshot,
            registry_auth: None,
            signature_validator: None,
            registry_handler: None,
            config,
            layer_store,
        }
    }

    /// pull_image pulls an image with optional auth info and decrypt config
    /// and store the pulled data under user defined work_dir/layers.
    /// It will return the image ID with prepared bundle: a rootfs directory,
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
    ) -> PullImageResult<ImageInfo> {
        let reference = Reference::try_from(image_url)
            .map_err(|source| PullImageError::IllegalImageReference { source })?;

        let tasks = match &self.registry_handler {
            Some(handler) => handler
                .process(reference)
                .map_err(|source| PullImageError::IllegalRegistryConfigurationFormat { source })?,
            None => vec![ImagePullTask {
                image_reference: reference,
                use_http: false,
                task_type: TaskType::Origininal,
            }],
        };

        let mut tried_images_and_errors = Vec::new();
        for task in tasks {
            let task_image_url = task.image_reference.to_string();
            match self
                .pull_task(task, auth_info, bundle_dir, decrypt_config, &task_image_url)
                .await
            {
                Ok(image_id) => return Ok(image_id),
                Err(e) => {
                    warn!("failed to pull image {image_url} from {task_image_url}: {e:#?}");
                    tried_images_and_errors.push(format!("image: {task_image_url}, error: {e}"));
                }
            }
        }

        Err(PullImageError::AllTasksTried {
            original_image_url: image_url.into(),
            tried_list: tried_images_and_errors.join("\n"),
        })
    }

    async fn pull_task(
        &mut self,
        task: ImagePullTask,
        auth_info: &Option<&str>,
        bundle_dir: &Path,
        decrypt_config: &Option<&str>,
        image_url: &str,
    ) -> PullImageResult<ImageInfo> {
        // Try to find a valid registry auth. Logic order
        // 1. the input parameter
        // 2. from self.registry_auth
        // 3. use Anonymous auth
        let auth = match auth_info {
            Some(input_auth) => match input_auth.split_once(':') {
                Some((username, password)) => {
                    RegistryAuth::Basic(username.to_string(), password.to_string())
                }
                None => {
                    return Err(PullImageError::IllegalRegistryAuth {
                        image: image_url.into(),
                        auth_source: format!("input `{input_auth}`"),
                    })
                }
            },
            None => match &self.registry_auth {
                Some(registry_auth) => registry_auth
                    .credential_for_reference(&task.image_reference)
                    .await
                    .map_err(|_| PullImageError::IllegalRegistryAuth {
                        image: image_url.into(),
                        auth_source: "auth config".into(),
                    })?,
                None => {
                    info!("Use Anonymous image registry auth");
                    RegistryAuth::Anonymous
                }
            },
        };

        let mut client_config = ClientConfig::default();
        if task.use_http {
            client_config.protocol = ClientProtocol::Http;
        }

        if let Some(proxy_config) = &self.config.image_pull_proxy {
            if let Some(no_proxy) = &proxy_config.no_proxy {
                client_config.no_proxy = Some(no_proxy.clone())
            }

            if let Some(https_proxy) = &proxy_config.https_proxy {
                client_config.https_proxy = Some(https_proxy.clone());
                if task.task_type != TaskType::Origininal && !task.use_http {
                    warn!(
                        "The image pull try from {} will use the configured https proxy",
                        task.image_reference
                    );
                }
            }

            if let Some(http_proxy) = &proxy_config.http_proxy {
                client_config.http_proxy = Some(http_proxy.clone());
                if task.task_type != TaskType::Origininal && task.use_http {
                    warn!(
                        "The image pull try from {} will use the configured http proxy",
                        task.image_reference
                    );
                }
            }
        }

        let certs = self
            .config
            .extra_root_certificates
            .iter()
            .map(|pem| pem.as_bytes())
            .map(|data| Certificate {
                encoding: CertificateEncoding::Pem,
                data: data.to_vec(),
            });
        client_config.extra_root_certificates.extend(certs);

        let mut client = PullClient::new(
            task.image_reference,
            self.layer_store.clone(),
            &auth,
            self.config.max_concurrent_layer_downloads_per_image,
            client_config,
        )
        .map_err(|source| PullImageError::Internal { source })?;
        let (image_manifest, image_digest, image_config) = client.pull_manifest().await?;

        let id = image_manifest.config.digest.clone();

        // If image has already been populated, just create the bundle.
        {
            let m = self.meta_store.read().await;
            if let Some(image_data) = &m.image_db.get(&id) {
                let image_id = create_bundle(image_data, bundle_dir, &mut self.snapshot)
                    .map_err(|source| PullImageError::FailedToCreateBundle { source })?;
                return Ok(ImageInfo {
                    config_digest: image_id.clone(),
                    manifest_digest: image_digest.clone(),
                });
            }
        }

        #[cfg(feature = "signature")]
        if let Some(signature_validator) = &self.signature_validator {
            signature_validator
                .check_image_signature(image_url, &image_digest, &auth)
                .await?;
        }

        let (mut image_data, unique_layers, unique_diff_ids) = create_image_meta(
            &id,
            image_url,
            &image_manifest,
            &image_digest,
            &image_config,
        )
        .map_err(|source| PullImageError::Internal { source })?;

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
            return Err(PullImageError::NotAllUniqueLayersPulled(
                unique_layers_len - image_data.layer_metas.len(),
            ));
        }

        let image_id = create_bundle(&image_data, bundle_dir, &mut self.snapshot)
            .map_err(|source| PullImageError::FailedToCreateBundle { source })?;

        debug!("image id: {image_id}");
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
            .context("update meta store failed")
            .map_err(|source| PullImageError::Internal { source })?;
        Ok(ImageInfo {
            config_digest: image_id.clone(),
            manifest_digest: image_digest.clone(),
        })
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
) -> anyhow::Result<(ImageMeta, Vec<OciDescriptor>, Vec<String>)> {
    let image_data = ImageMeta {
        id: id.to_string(),
        digest: image_digest.to_string(),
        reference: image_url.to_string(),
        image_config: ImageConfiguration::from_reader(image_config.as_bytes())?,
        ..Default::default()
    };

    let diff_ids = image_data.image_config.rootfs().diff_ids();
    if diff_ids.len() != image_manifest.layers.len() {
        bail!("Pulled number of layers mismatch with image config diff_ids");
    }

    // Note that an image's `diff_ids` may always refer to plaintext layer
    // digests. For two encryption layers encrypted from a same plaintext
    // layer, the `LayersData.Digest` of the image manifest might be different
    // because the symmetric key to encrypt is different, thus the cipher text
    // is different. Interestingly in such case the `diff_ids` of the both
    // layers are the same in the config.json.
    // Another note is that the order of layers in the image config and the
    // image manifest will always be the same, so it is safe to use a same
    // index to lookup or mark a layer.
    let mut unique_layers = Vec::new();
    let mut unique_diff_ids = Vec::new();

    let mut digests = BTreeSet::new();

    for (i, diff_id) in diff_ids.iter().enumerate() {
        if digests.contains(&image_manifest.layers[i].digest) {
            continue;
        }

        digests.insert(&image_manifest.layers[i].digest);
        unique_layers.push(image_manifest.layers[i].clone());
        unique_diff_ids.push(diff_id.to_string());
    }

    Ok((image_data, unique_layers, unique_diff_ids))
}

fn create_bundle(
    image_data: &ImageMeta,
    bundle_dir: &Path,
    snapshot: &mut Box<dyn Snapshotter>,
) -> anyhow::Result<String> {
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
            // KNOWN ISSUE: Uncompressed layer images fail due to astral-tokio-tar bug
            // See: https://github.com/astral-sh/tokio-tar/issues/...
            // "ghcr.io/mkulke/confidential-containers/faulty-image:1",
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
            panic!("failed to download image: {e}");
        }

        // Pull image again.
        let bundle2_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle2_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {e}");
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
            panic!("failed to download image: {e}");
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
            panic!("failed to download image: {e}");
        }

        // Verify that the "layers" directory does not exist in the second work directory
        // This confirms that the second image client reused the meta store and layers from the first image client
        assert!(!work_dir_2.path().join("layers").exists());
    }
}
