// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use futures_util::future;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::{secrets::RegistryAuth, Client, Reference};
use sha2::Digest;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::decoder::Compression;
use crate::decrypt::Decryptor;
use crate::image::LayerMeta;
use crate::meta_store::MetaStore;
use crate::unpack::unpack;

const DIGEST_SHA256: &str = "sha256";
const DIGEST_SHA512: &str = "sha512";

const ERR_NO_DECRYPT_CFG: &str = "decrypt_config is None";
const ERR_BAD_UNCOMPRESSED_DIGEST: &str = "unsupported uncompressed digest format";
const ERR_BAD_COMPRESSED_DIGEST: &str = "unsupported compressed digest format";

/// The PullClient connects to remote OCI registry, pulls the container image,
/// and save the image layers under data_dir and return the layer meta info.
pub struct PullClient {
    /// `oci-distribuion` client to talk with remote OCI registry.
    pub client: Client,

    /// OCI registry auth info.
    pub auth: RegistryAuth,

    /// OCI image reference.
    pub reference: Reference,

    /// OCI image layer data store dir.
    pub data_dir: PathBuf,
}

impl PullClient {
    /// Constructs a new PullClient struct with provided image info,
    /// data store dir and optional remote registry auth info.
    pub fn new(image: &str, data_dir: &Path, auth_info: &Option<&str>) -> Result<PullClient> {
        let mut auth = RegistryAuth::Anonymous;
        if let Some(auth_info) = auth_info {
            if let Some((username, password)) = auth_info.split_once(':') {
                auth = RegistryAuth::Basic(username.to_string(), password.to_string());
            } else {
                return Err(anyhow!("Invalid authentication info ({:?})", auth_info));
            }
        }

        let reference = Reference::try_from(image)?;
        let client = Client::default();

        Ok(PullClient {
            client,
            auth,
            reference,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// pull_manifest pulls an image manifest and config data.
    pub async fn pull_manifest(&mut self) -> Result<(OciImageManifest, String, String)> {
        self.client
            .pull_manifest_and_config(&self.reference, &self.auth)
            .await
    }

    /// pull_layers pulls an image layers and do ondemand decrypt/decompress.
    /// It returns the layer metadata for layer db to track.
    pub async fn pull_layers(
        &self,
        layer_descs: Vec<OciDescriptor>,
        diff_ids: &[String],
        decrypt_config: &Option<&str>,
        meta_store: Arc<Mutex<MetaStore>>,
    ) -> Result<Vec<LayerMeta>> {
        let layer_metas = layer_descs.into_iter().enumerate().map(|(i, layer)| {
            let client = &self.client;
            let reference = &self.reference;
            let ms = meta_store.clone();

            async move {
                let mut layer_data: Vec<u8> = Vec::new();

                client
                    .pull_blob(reference, &layer.digest, &mut layer_data)
                    .await?;

                self.handle_layer(layer, diff_ids[i].clone(), decrypt_config, layer_data, ms)
                    .await
            }
        });

        let layer_metas = future::try_join_all(layer_metas).await?;

        Ok(layer_metas)
    }

    async fn handle_layer(
        &self,
        layer: OciDescriptor,
        diff_id: String,
        decrypt_config: &Option<&str>,
        layer_data: Vec<u8>,
        ms: Arc<Mutex<MetaStore>>,
    ) -> Result<LayerMeta> {
        let mut out: Vec<u8> = Vec::new();
        let plaintext_layer: Vec<u8>;

        let mut layer_meta = LayerMeta::default();
        let mut media_type_str: &str = layer.media_type.as_str();

        let decryptor = Decryptor::from_media_type(&layer.media_type);

        if decryptor.is_encrypted() {
            if let Some(dc) = decrypt_config {
                plaintext_layer = decryptor
                    .get_plaintext_layer(&layer, layer_data, dc)
                    .await?;
                media_type_str = decryptor.media_type.as_str();
                layer_meta.encrypted = true;
            } else {
                return Err(anyhow!(ERR_NO_DECRYPT_CFG));
            }
        } else {
            plaintext_layer = layer_data;
        }

        let layer_db = &ms.lock().await.layer_db;

        if let Some(layer_meta) = layer_db.get(&layer.digest) {
            return Ok(layer_meta.clone());
        }

        layer_meta.decoder = Compression::try_from(media_type_str)?;

        if layer_meta.decoder == Compression::Uncompressed {
            let digest = if diff_id.starts_with(DIGEST_SHA256) {
                format!(
                    "{}:{:x}",
                    DIGEST_SHA256,
                    sha2::Sha256::digest(plaintext_layer.as_slice())
                )
            } else if diff_id.starts_with(DIGEST_SHA512) {
                format!(
                    "{}:{:x}",
                    DIGEST_SHA512,
                    sha2::Sha512::digest(plaintext_layer.as_slice())
                )
            } else {
                return Err(anyhow!("{}: {:?}", ERR_BAD_UNCOMPRESSED_DIGEST, diff_id));
            };

            layer_meta.uncompressed_digest = digest.clone();
            layer_meta.compressed_digest = digest;
        } else {
            layer_meta.compressed_digest = layer.digest.clone();
            layer_meta
                .decoder
                .decompress(plaintext_layer.as_slice(), &mut out)?;

            if diff_id.starts_with(DIGEST_SHA256) {
                layer_meta.uncompressed_digest =
                    format!("{DIGEST_SHA256}:{:x}", sha2::Sha256::digest(&out));
            } else if diff_id.starts_with(DIGEST_SHA512) {
                layer_meta.uncompressed_digest =
                    format!("{DIGEST_SHA512}:{:x}", sha2::Sha512::digest(&out));
            } else {
                return Err(anyhow!("{}: {:?}", ERR_BAD_COMPRESSED_DIGEST, diff_id));
            }
        }

        // uncompressed digest should equal to the diff_ids in image_config.
        if layer_meta.uncompressed_digest != diff_id {
            return Err(anyhow!(
                "unequal uncompressed digest {:?} config diff_id {:?}",
                layer_meta.uncompressed_digest,
                diff_id
            ));
        }

        let store_path = format!(
            "{}/{}",
            self.data_dir.display(),
            &layer.digest.to_string().replace(':', "_")
        );

        let destination = Path::new(&store_path);

        if let Err(e) = unpack(out, destination) {
            fs::remove_dir_all(destination)?;
            return Err(e);
        }

        layer_meta.store_path = destination.display().to_string();

        Ok(layer_meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::ERR_BAD_MEDIA_TYPE;
    use flate2::write::GzEncoder;
    use oci_distribution::manifest::IMAGE_CONFIG_MEDIA_TYPE;
    use oci_spec::image::{ImageConfiguration, MediaType};
    use ocicrypt_rs::spec::MEDIA_TYPE_LAYER_ENC;
    use std::io::Write;
    use tempfile;

    use test_utils::assert_result;

    #[tokio::test]
    async fn test_pull_client() {
        let oci_images = vec![
            "docker.io/arronwang/busybox_gzip",
            "docker.io/arronwang/busybox_zstd",
            "docker.io/arronwang/busybox_encrypted",
        ];

        for image in oci_images.iter() {
            let tempdir = tempfile::tempdir().unwrap();
            let mut client = PullClient::new(image, tempdir.path(), &None).unwrap();
            let (image_manifest, _image_digest, image_config) =
                client.pull_manifest().await.unwrap();

            let image_config = ImageConfiguration::from_reader(image_config.as_bytes()).unwrap();
            let diff_ids = image_config.rootfs().diff_ids();

            let config_dir = std::env!("CARGO_MANIFEST_DIR");
            let keyprovider_config =
                format!("{}/{}", config_dir, "test_data/ocicrypt_keyprovider.conf");
            let decrypt_config = Path::new(config_dir)
                .join("test_data")
                .join("private_key_for_tests.pem:test");

            std::env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config);

            assert!(client
                .pull_layers(
                    image_manifest.layers.clone(),
                    diff_ids,
                    &Some(decrypt_config.to_str().unwrap()),
                    Arc::new(Mutex::new(MetaStore::default()))
                )
                .await
                .is_ok());
        }
    }

    #[tokio::test]
    async fn test_handle_layer() {
        let oci_image = "docker.io/arronwang/busybox_gzip";

        let bad_media_err = format!("{}: {}", ERR_BAD_MEDIA_TYPE, IMAGE_CONFIG_MEDIA_TYPE);

        let empty_diff_id = "";

        let default_layer = OciDescriptor::default();

        let encrypted_layer = OciDescriptor {
            media_type: MEDIA_TYPE_LAYER_ENC.to_string(),
            ..Default::default()
        };

        let uncompressed_layer = OciDescriptor {
            media_type: MediaType::ImageLayer.to_string(),
            ..Default::default()
        };

        let data: Vec<u8> = b"This is some text!".to_vec();

        let mut gzip_encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip_encoder.write_all(&data).unwrap();
        let gzip_compressed_bytes = gzip_encoder.finish().unwrap();

        let compressed_layer = OciDescriptor {
            media_type: MediaType::ImageLayerGzip.to_string(),
            ..Default::default()
        };

        let tempdir = tempfile::tempdir().unwrap();
        let mut client = PullClient::new(oci_image, tempdir.path(), &None).unwrap();

        let (_image_manifest, _image_digest, _image_config) = client.pull_manifest().await.unwrap();

        let meta_store = MetaStore::default();
        let ms = Arc::new(Mutex::new(meta_store));

        #[derive(Debug)]
        struct TestData<'a> {
            layer: OciDescriptor,
            diff_id: &'a str,
            decrypt_config: Option<&'a str>,
            layer_data: Vec<u8>,
            result: Result<LayerMeta>,
        }

        let tests = &[
            TestData {
                layer: default_layer.clone(),
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(anyhow!(bad_media_err.clone())),
            },
            TestData {
                layer: default_layer.clone(),
                diff_id: "foo",
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(anyhow!(bad_media_err.clone())),
            },
            TestData {
                layer: encrypted_layer,
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(anyhow!(ERR_NO_DECRYPT_CFG)),
            },
            TestData {
                layer: uncompressed_layer,
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(anyhow!(
                    "{}: {:?}",
                    ERR_BAD_UNCOMPRESSED_DIGEST,
                    empty_diff_id
                )),
            },
            TestData {
                layer: compressed_layer,
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: gzip_compressed_bytes,
                result: Err(anyhow!(
                    "{}: {:?}",
                    ERR_BAD_COMPRESSED_DIGEST,
                    empty_diff_id
                )),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{}]: {:?}", i, d);

            let result = client
                .handle_layer(
                    d.layer.clone(),
                    d.diff_id.to_string(),
                    &d.decrypt_config,
                    d.layer_data.clone(),
                    ms.clone(),
                )
                .await;

            let msg = format!("{}: result: {:?}", msg, result);

            assert_result!(d.result, result, msg);
        }
    }
}
