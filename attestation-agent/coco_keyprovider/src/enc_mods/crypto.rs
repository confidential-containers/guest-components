// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::{aead::Aead, aes::Aes256, Aes256Gcm, Key, Nonce};
use anyhow::*;
use strum::EnumString;

/// Only for sample
pub const HARDCODED_KEY: &[u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

#[derive(Default, EnumString)]
pub enum Algorithm {
    #[default]
    A256GCM,
    A256CTR,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::A256GCM => "A256GCM".into(),
            Algorithm::A256CTR => "A256CTR".into(),
        }
    }
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8], algorithm: &Algorithm) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::A256GCM => {
            use aes_gcm::KeyInit;
            let encryption_key = Key::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(encryption_key);
            let nonce = Nonce::from_slice(iv);
            cipher
                .encrypt(nonce, data.as_ref())
                .map_err(|e| anyhow!("Decrypt failed: {:?}", e))
        }
        Algorithm::A256CTR => {
            use ctr::cipher::{KeyIvInit, StreamCipher};
            let mut buf = data.to_vec();
            let mut cipher = ctr::Ctr128BE::<Aes256>::new(key.into(), iv.into());
            cipher.apply_keystream(&mut buf);
            Ok(buf)
        }
    }
}
