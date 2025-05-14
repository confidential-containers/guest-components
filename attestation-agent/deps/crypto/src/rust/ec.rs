// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    ec::{Curve, KeyWrapAlgorithm},
    AES_GCM_256_KEY_BITS,
};

use aes_gcm::aead::generic_array::GenericArray;
use aes_kw::{Kek, KekAes256};
use anyhow::{anyhow, Result};
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::FromEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    EncodedPoint, PublicKey as P256PublicKey, SecretKey,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub enum EcKeyPair {
    P256(P256EcKeyPair),
}

impl Default for EcKeyPair {
    fn default() -> Self {
        Self::P256(P256EcKeyPair::default())
    }
}

impl EcKeyPair {
    pub fn curve(&self) -> Curve {
        match self {
            Self::P256(_) => Curve::P256,
        }
    }

    pub fn secret_key(&self) -> &SecretKey {
        match self {
            Self::P256(p256) => p256.secret_key(),
        }
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        match self {
            Self::P256(p256) => p256.x(),
        }
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        match self {
            Self::P256(p256) => p256.y(),
        }
    }

    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        let pem = self.secret_key().to_pkcs8_pem(LineEnding::default())?;
        Ok(pem)
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        if let Ok(p256) = P256EcKeyPair::from_pkcs8_pem(pem) {
            return Ok(Self::P256(p256));
        };

        Err(anyhow!("invalid key type"))
    }

    pub fn unwrap_key(
        &self,
        encrypted_key: Vec<u8>,
        epk_x: Vec<u8>,
        epk_y: Vec<u8>,
        wrapping_algorithm: KeyWrapAlgorithm,
    ) -> Result<Vec<u8>> {
        match wrapping_algorithm {
            KeyWrapAlgorithm::EcdhEsA256Kw => {
                let secret_key = self.secret_key();
                let epk_x: [u8; 32] = epk_x
                    .try_into()
                    .map_err(|_| anyhow!("invalid bytes length of coordinates X"))?;
                let epk_y: [u8; 32] = epk_y
                    .try_into()
                    .map_err(|_| anyhow!("invalid bytes length of coordinates Y"))?;
                let epk_point = EncodedPoint::from_affine_coordinates(
                    &GenericArray::from(epk_x),
                    &GenericArray::from(epk_y),
                    false,
                );
                let public_key =
                    Into::<Option<_>>::into(P256PublicKey::from_encoded_point(&epk_point));
                let public_key: P256PublicKey = public_key.ok_or(anyhow!("invalid public key"))?;

                let z = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine())
                    .raw_secret_bytes()
                    .to_vec();

                let mut key_derivation_materials = Vec::new();
                let algorithm_str = KeyWrapAlgorithm::EcdhEsA256Kw.as_ref();
                key_derivation_materials
                    .extend_from_slice(&(algorithm_str.len() as u32).to_be_bytes());
                key_derivation_materials.extend_from_slice(algorithm_str.as_bytes());
                key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
                key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
                key_derivation_materials.extend_from_slice(&AES_GCM_256_KEY_BITS.to_be_bytes());
                let mut unwrapping_key = vec![0; 32];
                concat_kdf::derive_key_into::<rsa::sha2::Sha256>(
                    &z,
                    &key_derivation_materials,
                    &mut unwrapping_key,
                )
                .map_err(|e| anyhow!("failed to do concat KDF: {e:?}"))?;
                let unwrapping_key: [u8; 32] = unwrapping_key
                    .try_into()
                    .map_err(|_| anyhow!("invalid bytes length of AES wrapping key"))?;
                let unwrapping_key: KekAes256 = Kek::new(&GenericArray::from(unwrapping_key));
                let mut decrypted_key = vec![0; encrypted_key.len() - 8];
                unwrapping_key
                    .unwrap(&encrypted_key, &mut decrypted_key)
                    .map_err(|e| anyhow!("failed to unwrap key: {e:?}"))?;

                Ok(decrypted_key)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct P256EcKeyPair {
    secret_key: SecretKey,
    public_key: P256PublicKey,
}

impl Default for P256EcKeyPair {
    fn default() -> Self {
        let mut rng = rand_08::thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

impl P256EcKeyPair {
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_pem(pem)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        let x = EncodedPoint::from(self.public_key)
            .x()
            .ok_or(anyhow!("invalid public key: without coordinate X"))?
            .to_vec();
        Ok(x)
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        let y = EncodedPoint::from(self.public_key)
            .y()
            .ok_or(anyhow!("invalid public key: without coordinate Y"))?
            .to_vec();
        Ok(y)
    }
}
