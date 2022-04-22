// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use futures_util::future;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};
use oci_spec::image::MediaType;
use sha2::Digest;
use std::convert::TryFrom;
use std::fs;
use std::io::Cursor;
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
                let mut out: Vec<u8> = Vec::new();
                let mut layer_data: Vec<u8> = Vec::new();
                let reader;

                client
                    .pull_blob(reference, &layer.digest, &mut layer_data)
                    .await?;

                let mut layer_meta = LayerMeta::default();
                let mut media_type_str: &str = layer.media_type.as_str();

                let decryptor = Decryptor::from_media_type(&layer.media_type);
                if decryptor.is_encrypted() {
                    if let Some(dc) = decrypt_config {
                        reader = decryptor.get_plaintext_layer(&layer, layer_data, dc)?;
                        media_type_str = decryptor.media_type.as_str();
                        layer_meta.encrypted = true;
                    } else {
                        return Err(anyhow!("decrypt_config is None"));
                    }
                } else {
                    reader = Box::new(Cursor::new(layer_data));
                }

                let layer_db = &ms.lock().await.layer_db;
                if let Some(layer_meta) = layer_db.get(&layer.digest) {
                    return Ok::<_, anyhow::Error>(layer_meta.clone());
                }

                // convert docker layer media type to oci format
                if media_type_str == manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE {
                    media_type_str = manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE;
                }

                let media_type = MediaType::from(media_type_str);
                layer_meta.decoder = match media_type {
                    MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => {
                        Compression::Uncompressed
                    }
                    MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
                        Compression::Gzip
                    }
                    MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => {
                        Compression::Zstd
                    }
                    _ => return Err(anyhow!("unhandled media type: {}", &layer.media_type)),
                };

                if layer_meta.decoder == Compression::Uncompressed {
                    layer_meta.uncompressed_digest = layer.digest.clone();
                    layer_meta.compressed_digest = layer.digest.clone();
                } else {
                    layer_meta.compressed_digest = layer.digest.clone();
                    layer_meta.decoder.decompress(reader, &mut out)?;

                    if diff_ids[i].starts_with(DIGEST_SHA256) {
                        layer_meta.uncompressed_digest =
                            format!("{}:{:x}", DIGEST_SHA256, sha2::Sha256::digest(&out));
                    } else if diff_ids[i].starts_with(DIGEST_SHA512) {
                        layer_meta.uncompressed_digest =
                            format!("{}:{:x}", DIGEST_SHA512, sha2::Sha512::digest(&out));
                    } else {
                        return Err(anyhow!("unsupported digest format: {}", diff_ids[i]));
                    }
                }

                // uncompressed digest should equal to the diff_ids in image_config.
                if layer_meta.uncompressed_digest != diff_ids[i] {
                    return Err(anyhow!(
                        "unequal uncompressed digest {:?} config diff_id {:?}",
                        layer_meta.uncompressed_digest,
                        diff_ids[i]
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

                Ok::<_, anyhow::Error>(layer_meta)
            }
        });

        let layer_metas = future::try_join_all(layer_metas).await?;

        Ok(layer_metas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::image::ImageConfiguration;
    use tempfile;

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
}
