// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use oci_distribution::{secrets::RegistryAuth, Client, Reference};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::io::StreamReader;

use crate::decoder::Compression;
use crate::decrypt::Decryptor;
use crate::image::LayerMeta;
use crate::meta_store::MetaStore;
use crate::stream::stream_processing;

const ERR_NO_DECRYPT_CFG: &str = "decrypt_config is None";

/// The PullClient connects to remote OCI registry, pulls the container image,
/// and save the image layers under data_dir and return the layer meta info.
pub struct PullClient<'a> {
    /// `oci-distribution` client to talk with remote OCI registry.
    pub client: Client,

    /// OCI registry auth info.
    pub auth: &'a RegistryAuth,

    /// OCI image reference.
    pub reference: Reference,

    /// OCI image layer data store dir.
    pub data_dir: PathBuf,

    /// Max number of concurrent downloads.
    pub max_concurrent_download: usize,
}

impl<'a> PullClient<'a> {
    /// Constructs a new PullClient struct with provided image info,
    /// data store dir and optional remote registry auth info.
    pub fn new(
        reference: Reference,
        data_dir: &Path,
        auth: &'a RegistryAuth,
        max_concurrent_download: usize,
    ) -> Result<PullClient<'a>> {
        let client = Client::default();

        Ok(PullClient {
            client,
            auth,
            reference,
            data_dir: data_dir.to_path_buf(),
            max_concurrent_download,
        })
    }

    /// pull_manifest pulls an image manifest and config data.
    pub async fn pull_manifest(&mut self) -> Result<(OciImageManifest, String, String)> {
        self.client
            .pull_manifest_and_config(&self.reference, self.auth)
            .await
            .map_err(|e| anyhow!("failed to pull manifest {}", e.to_string()))
    }

    /// pull_bootstrap pulls a nydus image's bootstrap layer.
    pub async fn pull_bootstrap(
        &self,
        bootstrap_desc: OciDescriptor,
        diff_id: String,
        decrypt_config: &Option<&str>,
        meta_store: Arc<Mutex<MetaStore>>,
    ) -> Result<LayerMeta> {
        let layer_metas = self
            .async_pull_layers(vec![bootstrap_desc], &[diff_id], decrypt_config, meta_store)
            .await?;
        match layer_metas.first() {
            Some(b) => Ok(b.clone()),
            None => Err(anyhow!("Failed to  download this bootstrap layer")),
        }
    }

    /// async_pull_layers pulls an image layers and do ondemand decrypt/decompress.
    /// It returns the layer metadata for layer db to track.
    pub async fn async_pull_layers(
        &self,
        layer_descs: Vec<OciDescriptor>,
        diff_ids: &[String],
        decrypt_config: &Option<&str>,
        meta_store: Arc<Mutex<MetaStore>>,
    ) -> Result<Vec<LayerMeta>> {
        let meta_store = &meta_store;
        let layer_metas: Vec<(usize, LayerMeta)> = stream::iter(layer_descs)
            .enumerate()
            .map(|(i, layer)| async move {
                let layer_stream = self
                    .client
                    .pull_blob_stream(&self.reference, &layer.digest)
                    .await
                    .map_err(|e| anyhow!("failed to async pull blob stream {}", e.to_string()))?;
                let layer_reader = StreamReader::new(layer_stream);
                self.async_handle_layer(
                    layer,
                    diff_ids[i].clone(),
                    decrypt_config,
                    layer_reader,
                    meta_store.clone(),
                )
                .await
                .map_err(|e| anyhow!("failed to handle layer: {:?}", e))
                .map(|layer_meta| (i, layer_meta))
            })
            .buffer_unordered(self.max_concurrent_download)
            .try_collect()
            .await?;
        let meta_map: BTreeMap<usize, _> = layer_metas.into_iter().collect();
        let sorted_layer_metas = meta_map.into_values().collect();
        Ok(sorted_layer_metas)
    }

    async fn async_handle_layer(
        &self,
        layer: OciDescriptor,
        diff_id: String,
        decrypt_config: &Option<&str>,
        layer_reader: (impl tokio::io::AsyncRead + Unpin + Send),
        ms: Arc<Mutex<MetaStore>>,
    ) -> Result<LayerMeta> {
        let layer_db = &ms.lock().await.layer_db;
        if let Some(layer_meta) = layer_db.get(&layer.digest) {
            return Ok(layer_meta.clone());
        }

        let blob_id = layer.digest.to_string().replace(':', "_");
        let destination = self.data_dir.join(blob_id);
        let mut layer_meta = LayerMeta {
            compressed_digest: layer.digest.clone(),
            store_path: destination.display().to_string(),
            ..Default::default()
        };

        let decryptor = Decryptor::from_media_type(&layer.media_type);
        if decryptor.is_encrypted() {
            if let Some(dc) = decrypt_config {
                let decrypt_key = decryptor
                    .get_decrypt_key(&layer, dc)
                    .map_err(|e| anyhow!("failed to get decrypt key {}", e.to_string()))?;
                let plaintext_layer = decryptor
                    .async_get_plaintext_layer(layer_reader, &layer, &decrypt_key)
                    .map_err(|e| anyhow!("failed to async_get_plaintext_layer: {:?}", e))?;
                layer_meta.uncompressed_digest = self
                    .async_decompress_unpack_layer(
                        plaintext_layer,
                        &diff_id,
                        &decryptor.media_type,
                        &destination,
                    )
                    .await?;
                layer_meta.encrypted = true;
            } else {
                bail!(ERR_NO_DECRYPT_CFG);
            }
        } else {
            layer_meta.uncompressed_digest = self
                .async_decompress_unpack_layer(
                    layer_reader,
                    &diff_id,
                    &layer.media_type,
                    &destination,
                )
                .await?;
        }

        // uncompressed digest should equal to the diff_ids in image_config.
        if layer_meta.uncompressed_digest != diff_id {
            bail!(
                "unequal uncompressed digest {:?} config diff_id {:?}",
                layer_meta.uncompressed_digest,
                diff_id
            );
        }

        Ok(layer_meta)
    }

    async fn async_decompress_unpack_layer(
        &self,
        input_reader: (impl tokio::io::AsyncRead + Unpin + Send),
        diff_id: &str,
        media_type: &str,
        destination: &Path,
    ) -> Result<String> {
        let decoder = Compression::try_from(media_type)?;
        let async_decoder = decoder.async_decompress(input_reader);
        stream_processing(async_decoder, diff_id, destination).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_MAX_CONCURRENT_DOWNLOAD;
    use crate::decoder::ERR_BAD_MEDIA_TYPE;
    use crate::ERR_BAD_UNCOMPRESSED_DIGEST;
    use flate2::write::GzEncoder;
    use oci_distribution::manifest::IMAGE_CONFIG_MEDIA_TYPE;
    use oci_spec::image::{ImageConfiguration, MediaType};
    use std::io::Write;
    use tempfile;

    use test_utils::{assert_result, assert_retry};

    #[ignore]
    #[tokio::test]
    async fn image_layer_order() {
        let image_url =
            "nginx@sha256:9700d098d545f9d2ee0660dfb155fe64f4447720a0a763a93f2cf08997227279";
        let tempdir = tempfile::tempdir().unwrap();
        let image = Reference::try_from(image_url.to_string()).expect("create reference failed");
        let mut client = PullClient::new(
            image,
            tempdir.path(),
            &RegistryAuth::Anonymous,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD,
        )
        .unwrap();
        let (image_manifest, _image_digest, image_config) = client.pull_manifest().await.unwrap();

        let image_config = ImageConfiguration::from_reader(image_config.as_bytes()).unwrap();
        let diff_ids = image_config.rootfs().diff_ids();

        // retry 3 times w/ timeout
        for i in 0..3 {
            let wait = std::time::Duration::from_secs(i * 2);
            tokio::time::sleep(wait).await;

            let result = client
                .async_pull_layers(
                    image_manifest.layers.clone(),
                    diff_ids,
                    &None,
                    Arc::new(Mutex::new(MetaStore::default())),
                )
                .await;
            if let Ok(layer_metas) = result {
                let digests: Vec<String> = layer_metas
                    .iter()
                    .map(|l| l.uncompressed_digest.clone())
                    .collect();
                assert_eq!(&digests, diff_ids, "hashes should be in same order");
                return;
            }
        }
        panic!("failed to pull layers");
    }

    #[tokio::test]
    async fn test_async_pull_client() {
        let oci_images = [
            "ghcr.io/confidential-containers/test-container-image-rs:busybox-gzip",
            "ghcr.io/confidential-containers/test-container-image-rs:busybox-zstd",
        ];

        for image_url in oci_images.iter() {
            let tempdir = tempfile::tempdir().unwrap();
            let image =
                Reference::try_from(image_url.to_string()).expect("create reference failed");
            let mut client = PullClient::new(
                image,
                tempdir.path(),
                &RegistryAuth::Anonymous,
                DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            )
            .unwrap();
            let (image_manifest, _image_digest, image_config) =
                client.pull_manifest().await.unwrap();

            let image_config = ImageConfiguration::from_reader(image_config.as_bytes()).unwrap();
            let diff_ids = image_config.rootfs().diff_ids();

            assert_retry!(
                5,
                1,
                client,
                async_pull_layers,
                image_manifest.layers.clone(),
                diff_ids,
                &None,
                Arc::new(Mutex::new(MetaStore::default()))
            );
        }
    }

    #[cfg(all(feature = "encryption", feature = "keywrap-jwe"))]
    #[tokio::test]
    async fn test_async_pull_client_encrypted() {
        let oci_images =
            ["ghcr.io/confidential-containers/test-container-image-rs:busybox-encrypted-jwe"];

        for image_url in oci_images.iter() {
            let tempdir = tempfile::tempdir().unwrap();
            let image =
                Reference::try_from(image_url.to_string()).expect("create reference failed");
            let mut client = PullClient::new(
                image,
                tempdir.path(),
                &RegistryAuth::Anonymous,
                DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            )
            .unwrap();
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

            assert_retry!(
                5,
                1,
                client,
                async_pull_layers,
                image_manifest.layers.clone(),
                diff_ids,
                &Some(decrypt_config.to_str().unwrap()),
                Arc::new(Mutex::new(MetaStore::default()))
            );
        }
    }

    #[tokio::test]
    async fn test_async_handle_layer() {
        let oci_image = Reference::try_from(
            "ghcr.io/confidential-containers/test-container-image-rs:busybox-gzip",
        )
        .expect("create reference failed");

        let bad_media_err = format!("{}: {}", ERR_BAD_MEDIA_TYPE, IMAGE_CONFIG_MEDIA_TYPE);

        let empty_diff_id = "";

        let default_layer = OciDescriptor::default();

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
        let mut client = PullClient::new(
            oci_image,
            tempdir.path(),
            &RegistryAuth::Anonymous,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD,
        )
        .unwrap();

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
            #[cfg(all(feature = "encryption", feature = "keywrap-grpc"))]
            TestData {
                layer: OciDescriptor {
                    media_type: ocicrypt_rs::spec::MEDIA_TYPE_LAYER_ENC.to_string(),
                    ..Default::default()
                },
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
                    ERR_BAD_UNCOMPRESSED_DIGEST,
                    empty_diff_id
                )),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{}]: {:?}", i, d);

            let result = client
                .async_handle_layer(
                    d.layer.clone(),
                    d.diff_id.to_string(),
                    &d.decrypt_config,
                    d.layer_data.clone().as_slice(),
                    ms.clone(),
                )
                .await;

            let msg = format!("{}: result: {:?}", msg, result);

            assert_result!(d.result, result, msg);
        }
    }

    #[cfg(feature = "nydus")]
    #[tokio::test]
    async fn test_pull_nydus_bootstrap() {
        let nydus_images =
            ["eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/v6/java:latest-test_nydus"];

        for image_url in nydus_images.iter() {
            let tempdir = tempfile::tempdir().unwrap();
            let image = Reference::try_from(*image_url).expect("create reference failed");
            let mut client = PullClient::new(
                image,
                tempdir.path(),
                &RegistryAuth::Anonymous,
                DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            )
            .unwrap();
            let (image_manifest, _image_digest, image_config) =
                client.pull_manifest().await.unwrap();

            let image_config = ImageConfiguration::from_reader(image_config.as_bytes()).unwrap();
            let diff_ids = image_config.rootfs().diff_ids();

            assert!(client
                .pull_bootstrap(
                    crate::nydus::utils::get_nydus_bootstrap_desc(&image_manifest).unwrap(),
                    diff_ids[diff_ids.len() - 1].to_string(),
                    &None,
                    Arc::new(Mutex::new(MetaStore::default())),
                )
                .await
                .is_ok());
        }
    }
}
