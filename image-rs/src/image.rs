// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use log::warn;
use nix::mount::MsFlags;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use oci_spec::image::{ImageConfiguration, Os};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryFrom;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::config::{ImageConfig, CONFIGURATION_FILE_PATH};
use crate::decoder::Compression;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::snapshots::{SnapshotType, Snapshotter};
use crate::verity::{self, DmVerityOption};

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

        #[allow(unused_mut)]
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
        // there will establish a secure channel between image-rs and Attestation-Agent
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

            if let Some(wrapped_aa_kbc_params) = decrypt_config {
                let wrapped_aa_kbc_params = wrapped_aa_kbc_params.to_string();
                let aa_kbc_params =
                    wrapped_aa_kbc_params.trim_start_matches("provider:attestation-agent:");

                // The secure channel to communicate with KBS.
                // This step will initialize the secure channel
                let mut channel = crate::resource::SECURE_CHANNEL.lock().await;
                *channel = Some(crate::resource::kbs::SecureChannel::new(aa_kbc_params).await?);
            } else {
                bail!("Secure channel creation needs aa_kbc_params.");
            }
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

/// mount_image_block_with_integrity creates a mapping backed by image block device <source_device_path> and
/// decoding <verity_options> for in-kernel verification. And mount the verity device
/// to <mount_path> with <mount_type>.
/// It will return the verity device path if succeeds and return an error if fails .
pub fn mount_image_block_with_integrity(
    verity_options: &str,
    source_device_path: &Path,
    mount_path: &Path,
    mount_type: &str,
) -> Result<String> {
    let parsed_data = DmVerityOption::try_from(verity_options)?;
    let verity_device_path = verity::create_verity_device(&parsed_data, source_device_path)?;

    nix::mount::mount(
        Some(verity_device_path.as_str()),
        mount_path,
        Some(mount_type),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    Ok(verity_device_path)
}
/// umount_image_block_with_integrity umounts the filesystem and closes the verity device named verity_device_name.
pub fn umount_image_block_with_integrity(
    mount_path: &Path,
    verity_device_name: String,
) -> Result<()> {
    nix::mount::umount(mount_path)?;
    verity::destroy_verity_device(verity_device_name)?;
    Ok(())
}

pub fn get_image_name_from_remote(image_url: &str) -> Result<String> {
    let image_name = image_url.trim_start_matches("imageurl=");
    let decoded = base64::engine::general_purpose::STANDARD.decode(image_name)?;

    Ok(String::from_utf8_lossy(&decoded).to_string())
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
    use base64::Engine;
    use std::fs;
    use std::process::Command;

    use test_utils::assert_retry;

    #[tokio::test]
    async fn test_pull_image() {
        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", work_dir.path());

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
            "docker.io/i386/busybox",
            // Google Container Registry
            "gcr.io/google-containers/busybox:1.27.2",
            // JFrog Container Registry
            // "releases-docker.jfrog.io/reg2/busybox:1.33.1"
        ];

        let mut image_client = ImageClient::default();
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
        std::env::set_var("CC_IMAGE_WORK_DIR", work_dir.path());

        let nydus_images = [
            "eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/v6/java:latest-test_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/ubuntu:latest_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/python:latest_nydus",
        ];

        let mut image_client = ImageClient::default();

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
    async fn test_mount_and_umount_image_block_with_integrity() {
        const VERITYSETUP_PATH: &[&str] = &["/sbin/veritysetup", "/usr/sbin/veritysetup"];
        //create a disk image file
        let work_dir = tempfile::tempdir().unwrap();
        let mount_dir = tempfile::tempdir().unwrap();
        let file_name: std::path::PathBuf = work_dir.path().join("test.file");
        let default_hash_type = "sha256";
        let default_data_block_size: u64 = 512;
        let default_data_block_num: u64 = 1024;
        let data_device_size = default_data_block_size * default_data_block_num;
        let default_hash_size: u64 = 4096;
        let default_resize_size: u64 = data_device_size * 4;
        let data = vec![0u8; data_device_size as usize];
        fs::write(&file_name, data)
            .unwrap_or_else(|err| panic!("Failed to write to file: {}", err));
        Command::new("mkfs")
            .args(["-t", "ext4", file_name.to_str().unwrap()])
            .output()
            .map_err(|err| format!("Failed to format disk image: {}", err))
            .unwrap_or_else(|err| panic!("{}", err));

        Command::new("truncate")
            .args([
                "-s",
                default_resize_size.to_string().as_str(),
                file_name.to_str().unwrap(),
            ])
            .output()
            .map_err(|err| format!("Failed to resize disk image: {}", err))
            .unwrap_or_else(|err| panic!("{}", err));

        //find an unused loop device and attach the file to the device
        let loop_control = loopdev::LoopControl::open().unwrap_or_else(|err| panic!("{}", err));
        let loop_device = loop_control
            .next_free()
            .unwrap_or_else(|err| panic!("{}", err));
        loop_device
            .with()
            .autoclear(true)
            .attach(file_name.to_str().unwrap())
            .unwrap_or_else(|err| panic!("{}", err));
        let loop_device_path = loop_device
            .path()
            .unwrap_or_else(|| panic!("failed to get loop device path"));
        let loop_device_path_str = loop_device_path
            .to_str()
            .unwrap_or_else(|| panic!("failed to get path string"));

        let mut verity_option = DmVerityOption {
            hashtype: default_hash_type.to_string(),
            blocksize: default_data_block_size,
            hashsize: default_hash_size,
            blocknum: default_data_block_num,
            offset: data_device_size,
            hash: "".to_string(),
        };

        // Calculates and permanently stores hash verification data for data_device.
        let veritysetup_bin = VERITYSETUP_PATH
            .iter()
            .find(|&path| Path::new(path).exists())
            .copied()
            .unwrap_or_else(|| panic!("Veritysetup path not found"));
        let output = Command::new(veritysetup_bin)
            .args([
                "format",
                "--no-superblock",
                "--format=1",
                "-s",
                "",
                &format!("--hash={}", verity_option.hashtype),
                &format!("--data-block-size={}", verity_option.blocksize),
                &format!("--hash-block-size={}", verity_option.hashsize),
                "--data-blocks",
                &format!("{}", verity_option.blocknum),
                "--hash-offset",
                &format!("{}", verity_option.offset),
                loop_device_path_str,
                loop_device_path_str,
            ])
            .output()
            .unwrap_or_else(|err| panic!("{}", err));
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            let hash_strings: Vec<&str> = lines[lines.len() - 1].split_whitespace().collect();
            verity_option.hash = hash_strings[2].to_string()
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr);
            panic!("Failed to create hash device: {}", error_message);
        }

        let serialized_option = serde_json::to_vec(&verity_option)
            .unwrap_or_else(|_| panic!("failed to serialize the options"));
        let encoded_option = base64::engine::general_purpose::STANDARD.encode(serialized_option);
        let res = mount_image_block_with_integrity(
            encoded_option.as_str(),
            &loop_device_path,
            mount_dir.path(),
            "ext4",
        )
        .unwrap_or_else(|err| panic!("Failed to mount image block with integrity {:?}", err));
        assert!(res.contains("/dev/mapper"));
        let verity_device_name = match verity::get_verity_device_name(encoded_option.as_str()) {
            Ok(name) => name,
            Err(err) => {
                panic!("Error getting verity device name: {}", err);
            }
        };
        assert!(umount_image_block_with_integrity(mount_dir.path(), verity_device_name).is_ok());
    }

    #[tokio::test]
    async fn test_image_reuse() {
        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", work_dir.path());

        let image = "mcr.microsoft.com/hello-world";

        let mut image_client = ImageClient::default();

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

    #[tokio::test]
    async fn test_get_image_name_from_remote() {
        let image_url = "imageurl=cmVnaXN0cnkuY24taGFuZ3pob3UuYWxpeXVuY3MuY29tL2dvb2dsZV9jb250YWluZXJzL3BhdXNlOjMuNg==";
        let image_name = "registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.6";
        assert_eq!(get_image_name_from_remote(image_url).unwrap(), image_name);
    }
}
