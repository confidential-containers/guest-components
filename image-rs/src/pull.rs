// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use oci_client::{
    client::ClientConfig,
    manifest::{OciDescriptor, OciImageManifest},
    secrets::RegistryAuth,
    Client, Reference,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio_util::io::StreamReader;

use crate::decoder::Compression;
use crate::layer_store::LayerStore;
use crate::meta_store::MetaStore;
use crate::stream::stream_processing;
use crate::{
    decoder::DecodeError,
    decrypt::{DecryptLayerError, Decryptor},
};
use crate::{image::LayerMeta, stream::StreamError};

pub type PullLayerResult<T> = std::result::Result<T, PullLayerError>;

#[derive(Error, Debug)]
pub enum PullLayerError {
    #[error("failed to pull image manifest: {source}")]
    PullManifestError {
        #[source]
        source: oci_client::errors::OciDistributionError,
    },

    #[error("Failed to download bootstrap layer")]
    PullBootstrapLayerError,

    #[error("Failed to async pull blob stream")]
    PullBlobStramFailed {
        #[source]
        source: oci_client::errors::OciDistributionError,
    },

    #[error("Internal async rumtine error for tokio")]
    RuntimeError(#[from] tokio::task::JoinError),

    #[error("Failed to decrypt layer: {0}")]
    ImageDecryptionFailed(#[from] DecryptLayerError),

    #[error("unequal uncompressed digest {uncompressed_digest} config diff_id {diff_id}")]
    UnequalUncompressedDigest {
        uncompressed_digest: String,
        diff_id: String,
    },

    #[error("Failed to decode layer: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("Failed to decode layer data stream: {0}")]
    HandleStreamError(#[from] StreamError),
}

/// The PullClient connects to remote OCI registry, pulls the container image,
/// and save the image layers under the layer store and return the layer meta info.
pub struct PullClient<'a> {
    /// `oci-client` to talk with remote OCI registry.
    pub client: Client,

    /// OCI registry auth info.
    pub auth: &'a RegistryAuth,

    /// OCI image reference.
    pub reference: Reference,

    /// The image layer store
    pub layer_store: LayerStore,

    /// Max number of concurrent downloads.
    pub max_concurrent_download: usize,
}

impl<'a> PullClient<'a> {
    /// Constructs a new PullClient struct with provided image info,
    /// data store dir and optional remote registry auth info.
    pub fn new(
        reference: Reference,
        layer_store: LayerStore,
        auth: &'a RegistryAuth,
        max_concurrent_download: usize,
        client_config: ClientConfig,
    ) -> Result<PullClient<'a>> {
        let client = Client::try_from(client_config)?;

        Ok(PullClient {
            client,
            auth,
            reference,
            layer_store,
            max_concurrent_download,
        })
    }

    /// pull_manifest pulls an image manifest and config data.
    pub async fn pull_manifest(&mut self) -> PullLayerResult<(OciImageManifest, String, String)> {
        self.client
            .pull_manifest_and_config(&self.reference, self.auth)
            .await
            .map_err(|source| PullLayerError::PullManifestError { source })
    }

    /// async_pull_layers pulls an image layers and do ondemand decrypt/decompress.
    /// It returns the layer metadata for layer db to track.
    pub async fn async_pull_layers(
        &self,
        layer_descs: Vec<OciDescriptor>,
        diff_ids: &[String],
        decrypt_config: &Option<&str>,
        meta_store: Arc<RwLock<MetaStore>>,
    ) -> PullLayerResult<Vec<LayerMeta>> {
        let meta_store = &meta_store;
        let layer_metas: Vec<(usize, LayerMeta)> = stream::iter(layer_descs)
            .enumerate()
            .map(|(i, layer)| async move {
                let layer_stream = self
                    .client
                    .pull_blob_stream(&self.reference, &layer)
                    .await
                    .map_err(|source| PullLayerError::PullBlobStramFailed { source })?;
                let layer_reader = StreamReader::new(layer_stream.stream);
                self.async_handle_layer(
                    layer,
                    diff_ids[i].clone(),
                    decrypt_config,
                    layer_reader,
                    meta_store.clone(),
                )
                .await
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
        layer_reader: impl tokio::io::AsyncRead + Unpin + Send,
        ms: Arc<RwLock<MetaStore>>,
    ) -> PullLayerResult<LayerMeta> {
        if let Some(layer_meta) = ms.read().await.layer_db.get(&layer.digest) {
            return Ok(layer_meta.clone());
        }

        let destination = self.layer_store.new_layer_store_path();
        let mut layer_meta = LayerMeta {
            compressed_digest: layer.digest.clone(),
            store_path: destination.display().to_string(),
            ..Default::default()
        };

        let decryptor = Decryptor::from_media_type(&layer.media_type);

        // There are two types of layers:
        // 1. Compressed layer = Compress(Layer Data)
        // 2. Encrypted+Compressed layer = Compress(Encrypt(Layer Data))
        if decryptor.is_encrypted() {
            let decrypt_key = tokio::task::spawn_blocking({
                let decryptor = decryptor.clone();
                let layer = layer.clone();
                let decrypt_config = decrypt_config.as_ref().map(|inner| inner.to_string());
                move || decryptor.get_decrypt_key(&layer, &decrypt_config.as_deref())
            })
            .await??;
            let plaintext_layer =
                decryptor.async_get_plaintext_layer(layer_reader, &layer, &decrypt_key)?;
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
            return Err(PullLayerError::UnequalUncompressedDigest {
                uncompressed_digest: layer_meta.uncompressed_digest,
                diff_id,
            });
        }

        Ok(layer_meta)
    }

    /// Decompress and unpack layer data. The returned value is the
    /// digest of the uncompressed layer.
    async fn async_decompress_unpack_layer(
        &self,
        input_reader: impl tokio::io::AsyncRead + Unpin + Send,
        diff_id: &str,
        media_type: &str,
        destination: &Path,
    ) -> PullLayerResult<String> {
        let decoder = Compression::try_from(media_type)?;
        let async_decoder = decoder.async_decompress(input_reader);
        stream_processing(async_decoder, diff_id, destination)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_MAX_CONCURRENT_DOWNLOAD;
    use flate2::write::GzEncoder;
    use oci_client::manifest::IMAGE_CONFIG_MEDIA_TYPE;
    use oci_spec::image::{ImageConfiguration, MediaType};
    use std::io::Write;

    use test_utils::{assert_result, assert_retry};

    #[ignore]
    #[tokio::test]
    async fn image_layer_order() {
        let image_url =
            "nginx@sha256:9700d098d545f9d2ee0660dfb155fe64f4447720a0a763a93f2cf08997227279";
        let tempdir = tempfile::tempdir().unwrap();
        let image = Reference::try_from(image_url.to_string()).expect("create reference failed");
        let layer_store =
            LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");
        let client_config = ClientConfig::default();

        let mut client = PullClient::new(
            image,
            layer_store,
            &RegistryAuth::Anonymous,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            client_config,
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
                    Arc::new(RwLock::new(MetaStore::default())),
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
            let layer_store =
                LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");
            let client_config = ClientConfig::default();

            let mut client = PullClient::new(
                image,
                layer_store,
                &RegistryAuth::Anonymous,
                DEFAULT_MAX_CONCURRENT_DOWNLOAD,
                client_config,
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
                Arc::new(RwLock::new(MetaStore::default()))
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
            let layer_store =
                LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");
            let client_config = ClientConfig::default();

            let mut client = PullClient::new(
                image,
                layer_store,
                &RegistryAuth::Anonymous,
                DEFAULT_MAX_CONCURRENT_DOWNLOAD,
                client_config,
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
                Arc::new(RwLock::new(MetaStore::default()))
            );
        }
    }

    #[tokio::test]
    async fn test_async_handle_layer() {
        let oci_image = Reference::try_from(
            "ghcr.io/confidential-containers/test-container-image-rs:busybox-gzip",
        )
        .expect("create reference failed");

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
        let layer_store =
            LayerStore::new(tempdir.path().to_path_buf()).expect("create layer store failed");
        let client_config = ClientConfig::default();

        let mut client = PullClient::new(
            oci_image,
            layer_store,
            &RegistryAuth::Anonymous,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            client_config,
        )
        .unwrap();

        let (_image_manifest, _image_digest, _image_config) = client.pull_manifest().await.unwrap();

        let meta_store = MetaStore::default();
        let ms = Arc::new(RwLock::new(meta_store));

        #[derive(Debug)]
        struct TestData<'a> {
            layer: OciDescriptor,
            diff_id: &'a str,
            decrypt_config: Option<&'a str>,
            layer_data: Vec<u8>,
            result: PullLayerResult<LayerMeta>,
        }

        let tests = &[
            TestData {
                layer: default_layer.clone(),
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(PullLayerError::DecodeError(DecodeError::BadMediaType(
                    IMAGE_CONFIG_MEDIA_TYPE.into(),
                ))),
            },
            TestData {
                layer: default_layer.clone(),
                diff_id: "foo",
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(PullLayerError::DecodeError(DecodeError::BadMediaType(
                    IMAGE_CONFIG_MEDIA_TYPE.into(),
                ))),
            },
            TestData {
                layer: uncompressed_layer,
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: Vec::<u8>::new(),
                result: Err(PullLayerError::HandleStreamError(
                    StreamError::UnsupportedDigestFormat("".into()),
                )),
            },
            TestData {
                layer: compressed_layer,
                diff_id: empty_diff_id,
                decrypt_config: None,
                layer_data: gzip_compressed_bytes,
                result: Err(PullLayerError::HandleStreamError(
                    StreamError::UnsupportedDigestFormat("".into()),
                )),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let result = client
                .async_handle_layer(
                    d.layer.clone(),
                    d.diff_id.to_string(),
                    &d.decrypt_config,
                    d.layer_data.clone().as_slice(),
                    ms.clone(),
                )
                .await;

            let msg = format!("{msg}: result: {result:?}");

            assert_result!(d.result, result, msg);
        }
    }
}
