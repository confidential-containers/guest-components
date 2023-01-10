// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::unpack::unpack;
use crate::unpack::UnpackError;
use sha2::Digest;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinError;

const CAPACITY: usize = 32768;
const DIGEST_SHA256: &str = "sha256";
const DIGEST_SHA512: &str = "sha512";

pub trait DigestHasher {
    fn digest_update(&mut self, buf: &[u8]);
    fn digest_finalize(self) -> String;
}

#[derive(Clone, Debug)]
pub enum LayerDigestHasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("unsupported uncompressed digest format: {0}")]
    UnsupportedDigestFormat(String),

    #[error("failed to read from channel: {0}")]
    ChannelReadFailed(std::io::Error),

    #[error("failed to send to channel: {0}")]
    ChannelSendFailed(String),

    #[error("failed to roll back when unpacking: {0}")]
    UnpackRollbackFailed(UnpackError),

    #[error("unpack failed: {0}")]
    UnpackFailed(UnpackError),

    #[error("task join failed: {0}")]
    JoinFailed(JoinError),
}

type Result<T> = std::result::Result<T, StreamError>;

impl DigestHasher for LayerDigestHasher {
    fn digest_update(&mut self, buf: &[u8]) {
        match self {
            LayerDigestHasher::Sha256(hasher) => {
                hasher.update(buf);
            }
            LayerDigestHasher::Sha512(hasher) => {
                hasher.update(buf);
            }
        }
    }

    fn digest_finalize(self) -> String {
        match self {
            LayerDigestHasher::Sha256(hasher) => {
                format!("{}:{:x}", DIGEST_SHA256, hasher.finalize())
            }
            LayerDigestHasher::Sha512(hasher) => {
                format!("{}:{:x}", DIGEST_SHA512, hasher.finalize())
            }
        }
    }
}

// Wrap a flume channel with [`Read`](std::io::Read) support.
// This can bridge the [`AsyncRead`](tokio::io::AsyncRead) from
// decrypt/decompress and impl Read for unpack.
struct ChannelRead {
    rx: flume::Receiver<Vec<u8>>,
    current: Cursor<Vec<u8>>,
}

impl ChannelRead {
    fn new(rx: flume::Receiver<Vec<u8>>) -> ChannelRead {
        ChannelRead {
            rx,
            current: Cursor::new(vec![]),
        }
    }
}

impl Read for ChannelRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Receive new buffer when we finish handled previous data.
        if self.current.position() == self.current.get_ref().len() as u64 {
            if let Ok(buffer) = self.rx.recv() {
                self.current = Cursor::new(buffer);
            }

            // When recv() finished or failed, the sender will close the channel
            // which means EOF. The following read will also exit with EOF from
            // the exhausted cursor.
        }

        std::io::Read::read(&mut self.current, buf)
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

    let hasher = if diff_id.starts_with(DIGEST_SHA256) {
        LayerDigestHasher::Sha256(sha2::Sha256::new())
    } else if diff_id.starts_with(DIGEST_SHA512) {
        LayerDigestHasher::Sha512(sha2::Sha512::new())
    } else {
        return Err(StreamError::UnsupportedDigestFormat(diff_id.into()));
    };

    let digest_str = channel_processing(layer_reader, hasher, dest).await?;

    Ok(digest_str)
}

async fn channel_processing(
    mut layer_reader: (impl AsyncRead + Unpin),
    mut hasher: LayerDigestHasher,
    destination: PathBuf,
) -> Result<String> {
    let (tx, rx) = flume::unbounded();
    let unpack_thread = std::thread::spawn(move || -> std::result::Result<(), UnpackError> {
        let mut input = ChannelRead::new(rx);

        if let Err(e) = unpack(&mut input, destination.as_path()) {
            fs::remove_dir_all(destination.as_path())
                .map_err(|e| UnpackError::UnpackDirRemoveFailed(e))?;

            return Err(e);
        }

        Ok(())
    });

    let mut buffer = [0; CAPACITY];
    loop {
        let n = layer_reader
            .read(&mut buffer)
            .await
            .map_err(|e| StreamError::ChannelReadFailed(e))?;
        if n == 0 {
            break;
        }

        hasher.digest_update(&buffer[..n]);
        tx.send_async(buffer[..n].to_vec())
            .await
            .map_err(|e| StreamError::ChannelSendFailed(e.to_string()))?;
    }

    // Close the channel to signal EOF.
    drop(tx);

    tokio::task::spawn_blocking(|| unpack_thread.join().unwrap())
        .await
        .map_err(|e| StreamError::JoinFailed(e))?
        .map_err(|e| StreamError::UnpackFailed(e))?;

    Ok(hasher.digest_finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rand::rand_bytes;
    use std::fs::File;
    use std::io::BufReader;
    use tar::{Builder, Header};
    use tempfile;

    #[tokio::test]
    async fn test_channel_processing() {
        let mut data = [0; 100000];
        rand_bytes(&mut data).unwrap();
        let data_digest = sha2::Sha256::digest(data.as_slice());

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .unwrap();

        let layer_data = ar.into_inner().unwrap();

        let layer_digest = format!(
            "{}:{:x}",
            DIGEST_SHA256,
            sha2::Sha256::digest(layer_data.as_slice())
        );

        let tempdir = tempfile::tempdir().unwrap();
        let file_path = tempdir.path().join("layer0");

        let hasher = LayerDigestHasher::Sha256(sha2::Sha256::new());

        let layer_digest_new =
            channel_processing(layer_data.as_slice(), hasher, file_path.to_path_buf())
                .await
                .unwrap();
        assert_eq!(layer_digest, layer_digest_new);

        let file = File::open(file_path.join("file.txt")).unwrap();
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();

        reader.read_to_end(&mut buffer).unwrap();
        let data_digest_new = sha2::Sha256::digest(buffer);
        assert_eq!(data_digest, data_digest_new);
    }

    #[tokio::test]
    async fn test_stream_processing() {
        let mut data = [0; 100000];
        rand_bytes(&mut data).unwrap();

        let mut ar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(100000);
        header.set_cksum();
        ar.append_data(&mut header, "file.txt", data.as_slice())
            .unwrap();

        let layer_data = ar.into_inner().unwrap();

        let layer_digest = format!(
            "{}:{:x}",
            DIGEST_SHA256,
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
            "{}:{:x}",
            DIGEST_SHA512,
            sha2::Sha512::digest(layer_data.as_slice())
        );

        let layer_digest_new = stream_processing(layer_data.as_slice(), &layer_digest, &file_path)
            .await
            .unwrap();
        assert_eq!(layer_digest, layer_digest_new);
    }
}
