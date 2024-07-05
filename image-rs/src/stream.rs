// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use sha2::Digest;
use std::{
    path::{Path, PathBuf},
    pin::Pin,
    task::Poll,
};
use tokio::io::{AsyncRead, ReadBuf};

use crate::digest::{DigestHasher, LayerDigestHasher, DIGEST_SHA256_PREFIX, DIGEST_SHA512_PREFIX};
use crate::unpack::unpack;
use crate::ERR_BAD_UNCOMPRESSED_DIGEST;

struct HashReader<R, H> {
    reader: R,
    hasher: H,
}

impl<R, H> HashReader<R, H>
where
    R: AsyncRead,
    H: DigestHasher,
{
    pub fn new(reader: R, hasher: H) -> Self {
        HashReader { reader, hasher }
    }
}

impl<R, H> AsyncRead for HashReader<R, H>
where
    R: AsyncRead + Unpin,
    H: DigestHasher + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let old_position = buf.filled().len();
        let me = &mut *self;
        match Pin::new(&mut me.reader).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = buf.filled();
                let new_position = bytes.len();
                self.hasher
                    .digest_update(&bytes[old_position..new_position]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// stream_processing will handle async uncompressed layer data and
/// unpack to the destination, returns layer digest for verification.
pub async fn stream_processing(
    layer_reader: impl AsyncRead + Unpin,
    diff_id: &str,
    destination: &Path,
) -> Result<String> {
    let dest = destination.to_path_buf();
    let hasher = if diff_id.starts_with(DIGEST_SHA256_PREFIX) {
        LayerDigestHasher::Sha256(sha2::Sha256::new())
    } else if diff_id.starts_with(DIGEST_SHA512_PREFIX) {
        LayerDigestHasher::Sha512(sha2::Sha512::new())
    } else {
        bail!("{}: {:?}", ERR_BAD_UNCOMPRESSED_DIGEST, diff_id);
    };

    async_processing(layer_reader, hasher, dest)
        .await
        .map_err(|e| anyhow!("hasher {} {:?}", DIGEST_SHA256_PREFIX, e))
}

async fn async_processing(
    layer_reader: (impl AsyncRead + Unpin),
    hasher: LayerDigestHasher,
    destination: PathBuf,
) -> Result<String> {
    let mut hash_reader = HashReader::new(layer_reader, hasher);
    if let Err(e) = unpack(&mut hash_reader, destination.as_path()).await {
        error!("failed to unpack layer: {e:?}");
        tokio::fs::remove_dir_all(destination.as_path())
            .await
            .context("Failed to roll back when unpacking")?;
        return Err(e);
    }

    Ok(hash_reader.hasher.digest_finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SecureRandom;
    use tokio::{
        fs::File,
        io::{AsyncReadExt, BufReader},
    };
    use tokio_tar::{Builder, Header};

    #[tokio::test]
    async fn test_async_processing() {
        let mut data = [0; 100000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();
        let data_digest = sha2::Sha256::digest(data.as_slice());

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        header.set_uid(0);
        header.set_gid(0);
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .await
            .unwrap();

        let layer_data = ar.into_inner().await.unwrap();

        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA256_PREFIX,
            sha2::Sha256::digest(layer_data.as_slice())
        );

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer0");

        let hasher = LayerDigestHasher::Sha256(sha2::Sha256::new());

        let layer_digest_new =
            async_processing(layer_data.as_slice(), hasher, file_path.to_path_buf())
                .await
                .unwrap();
        assert_eq!(layer_digest, layer_digest_new);

        let file = File::open(file_path.join("file.txt")).await.unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).await.unwrap();
        let data_digest_new = sha2::Sha256::digest(buffer);
        assert_eq!(data_digest, data_digest_new);
    }

    #[tokio::test]
    async fn test_stream_processing() {
        let mut data = [0; 100000];
        ring::rand::SystemRandom::new().fill(&mut data[..]).unwrap();

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        header.set_uid(0);
        header.set_gid(0);
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .await
            .unwrap();

        let layer_data = ar.into_inner().await.unwrap();

        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA256_PREFIX,
            sha2::Sha256::digest(layer_data.as_slice())
        );

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer0");

        let layer_digest_new = stream_processing(layer_data.as_slice(), &layer_digest, &file_path)
            .await
            .unwrap();
        assert_eq!(layer_digest, layer_digest_new);

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer1");
        let layer_digest = format!(
            "{}{:x}",
            DIGEST_SHA512_PREFIX,
            sha2::Sha512::digest(layer_data.as_slice())
        );

        let layer_digest_new = stream_processing(layer_data.as_slice(), &layer_digest, &file_path)
            .await
            .unwrap();
        assert_eq!(layer_digest, layer_digest_new);
    }
}
