// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use sha2::Digest;

pub const DIGEST_SHA256_PREFIX: &str = "sha256:";
pub const DIGEST_SHA512_PREFIX: &str = "sha512:";

pub trait DigestHasher {
    fn digest_update(&mut self, buf: &[u8]);
    fn digest_finalize(self) -> String;
}

#[derive(Clone, Debug)]
pub enum LayerDigestHasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

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
                format!("{}{:x}", DIGEST_SHA256_PREFIX, hasher.finalize())
            }
            LayerDigestHasher::Sha512(hasher) => {
                format!("{}{:x}", DIGEST_SHA512_PREFIX, hasher.finalize())
            }
        }
    }
}
