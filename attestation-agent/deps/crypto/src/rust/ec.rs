// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    ec::{Curve, KeyWrapAlgorithm},
    AES_GCM_256_KEY_BITS,
};

use aes_kw::{KeyInit, KwAes256};
use anyhow::{anyhow, Result};
use p256::{
    ecdh::diffie_hellman as diffie_hellman_p256,
    elliptic_curve::sec1::FromEncodedPoint,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    EncodedPoint as P256EncodedPoint, FieldBytes as P256FieldBytes, PublicKey as P256PublicKey,
    SecretKey as P256SecretKey,
};
use p521::{
    ecdh::diffie_hellman as diffie_hellman_p521, EncodedPoint as P521EncodedPoint,
    FieldBytes as P521FieldBytes, PublicKey as P521PublicKey, SecretKey as P521SecretKey,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub enum EcKeyPair {
    P256(P256EcKeyPair),
    P521(P521EcKeyPair),
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
            Self::P521(_) => Curve::P521,
        }
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        match self {
            Self::P256(p256) => p256.x(),
            Self::P521(p521) => p521.x(),
        }
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        match self {
            Self::P256(p256) => p256.y(),
            Self::P521(p521) => p521.y(),
        }
    }

    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        match self {
            Self::P256(p256) => Ok(p256.secret_key().to_pkcs8_pem(LineEnding::default())?),
            Self::P521(p521) => Ok(p521.secret_key().to_pkcs8_pem(LineEnding::default())?),
        }
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        if let Ok(p256) = P256EcKeyPair::from_pkcs8_pem(pem) {
            return Ok(Self::P256(p256));
        };
        if let Ok(p521) = P521EcKeyPair::from_pkcs8_pem(pem) {
            return Ok(Self::P521(p521));
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
                let z = match self {
                    Self::P256(p256) => {
                        let epk_x: [u8; 32] = epk_x
                            .clone()
                            .try_into()
                            .map_err(|_| anyhow!("invalid bytes length of coordinates X"))?;
                        let epk_y: [u8; 32] = epk_y
                            .clone()
                            .try_into()
                            .map_err(|_| anyhow!("invalid bytes length of coordinates Y"))?;
                        let epk_point = P256EncodedPoint::from_affine_coordinates(
                            P256FieldBytes::from_slice(&epk_x),
                            P256FieldBytes::from_slice(&epk_y),
                            false,
                        );
                        let public_key =
                            Into::<Option<_>>::into(P256PublicKey::from_encoded_point(&epk_point));
                        let public_key: P256PublicKey =
                            public_key.ok_or(anyhow!("invalid public key"))?;
                        diffie_hellman_p256(
                            p256.secret_key().to_nonzero_scalar(),
                            public_key.as_affine(),
                        )
                        .raw_secret_bytes()
                        .to_vec()
                    }
                    Self::P521(p521) => {
                        let epk_x: [u8; 66] = epk_x
                            .clone()
                            .try_into()
                            .map_err(|_| anyhow!("invalid bytes length of coordinates X"))?;
                        let epk_y: [u8; 66] = epk_y
                            .clone()
                            .try_into()
                            .map_err(|_| anyhow!("invalid bytes length of coordinates Y"))?;
                        let epk_point = P521EncodedPoint::from_affine_coordinates(
                            P521FieldBytes::from_slice(&epk_x),
                            P521FieldBytes::from_slice(&epk_y),
                            false,
                        );
                        let public_key =
                            Into::<Option<_>>::into(P521PublicKey::from_encoded_point(&epk_point));
                        let public_key: P521PublicKey =
                            public_key.ok_or(anyhow!("invalid public key"))?;
                        diffie_hellman_p521(
                            p521.secret_key().to_nonzero_scalar(),
                            public_key.as_affine(),
                        )
                        .raw_secret_bytes()
                        .to_vec()
                    }
                };

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
                let unwrapping_key = KwAes256::new(&unwrapping_key.into());
                let mut decrypted_key = vec![0; encrypted_key.len() - 8];
                unwrapping_key
                    .unwrap_key(&encrypted_key, &mut decrypted_key)
                    .map_err(|e| anyhow!("failed to unwrap key: {e:?}"))?;

                Ok(decrypted_key)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct P256EcKeyPair {
    secret_key: P256SecretKey,
    public_key: P256PublicKey,
}

impl Default for P256EcKeyPair {
    fn default() -> Self {
        let mut rng = rand_08::thread_rng();
        let secret_key = P256SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

impl P256EcKeyPair {
    pub fn secret_key(&self) -> &P256SecretKey {
        &self.secret_key
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let secret_key = P256SecretKey::from_pkcs8_pem(pem)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        let x = P256EncodedPoint::from(self.public_key)
            .x()
            .ok_or(anyhow!("invalid public key: without coordinate X"))?
            .to_vec();
        Ok(x)
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        let y = P256EncodedPoint::from(self.public_key)
            .y()
            .ok_or(anyhow!("invalid public key: without coordinate Y"))?
            .to_vec();
        Ok(y)
    }
}

#[derive(Clone, Debug)]
pub struct P521EcKeyPair {
    secret_key: P521SecretKey,
    public_key: P521PublicKey,
}

impl Default for P521EcKeyPair {
    fn default() -> Self {
        let mut rng = rand_08::thread_rng();
        let secret_key = P521SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }
}

impl P521EcKeyPair {
    pub fn secret_key(&self) -> &P521SecretKey {
        &self.secret_key
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let secret_key = P521SecretKey::from_pkcs8_pem(pem)?;
        let public_key = secret_key.public_key();
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        let x = P521EncodedPoint::from(self.public_key)
            .x()
            .ok_or(anyhow!("invalid public key: without coordinate X"))?
            .to_vec();
        Ok(x)
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        let y = P521EncodedPoint::from(self.public_key)
            .y()
            .ok_or(anyhow!("invalid public key: without coordinate Y"))?
            .to_vec();
        Ok(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_curve_is_p256() {
        assert!(matches!(EcKeyPair::default(), EcKeyPair::P256(_)));
    }

    #[test]
    fn p521_roundtrip_and_coordinates() {
        let p521 = EcKeyPair::P521(P521EcKeyPair::default());
        assert!(matches!(p521.curve(), Curve::P521));
        assert_eq!(p521.x().expect("x should exist").len(), 66);
        assert_eq!(p521.y().expect("y should exist").len(), 66);

        let pem = p521.to_pkcs8_pem().expect("serialize pem");
        let parsed = EcKeyPair::from_pkcs8_pem(&pem).expect("parse pem");
        assert!(matches!(parsed.curve(), Curve::P521));
    }
}
