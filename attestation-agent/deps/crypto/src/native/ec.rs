// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use openssl::{
    aes::{self, AesKey},
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private},
};
use zeroize::Zeroizing;

use crate::{
    ec::{Curve, KeyWrapAlgorithm},
    AES_GCM_256_KEY_BITS,
};

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
    fn private_key(&self) -> &PKey<Private> {
        match self {
            Self::P256(p256) => p256.private_key(),
        }
    }

    pub fn curve(&self) -> Curve {
        match self {
            Self::P256(_) => Curve::P256,
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
        let pem = self.private_key().private_key_to_pem_pkcs8()?;
        let pem = String::from_utf8(pem).map_err(|_| anyhow!("invalid pem"))?;
        Ok(Zeroizing::new(pem))
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let private_key = PKey::private_key_from_pem(pem.as_bytes())?;
        let ec_key = private_key.ec_key().context("must be a ec key")?;
        let curve_nid = ec_key
            .group()
            .curve_name()
            .ok_or(anyhow!("failed to get curve name"))?;
        match curve_nid {
            Nid::X9_62_PRIME256V1 => Ok(Self::P256(P256EcKeyPair { private_key })),
            _ => bail!("unsupported EC curve with NID {curve_nid:?}"),
        }
    }

    pub fn unwrap_key(
        &self,
        encrypted_key: Vec<u8>,
        epk_x: Vec<u8>,
        epk_y: Vec<u8>,
        wrapping_algorithm: KeyWrapAlgorithm,
    ) -> Result<Vec<u8>> {
        let group = match self.curve() {
            Curve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
        };
        let point = group.generator();
        let mut point = point.to_owned(&group)?;

        let epk_x = BigNum::from_slice(&epk_x)?;
        let epk_y = BigNum::from_slice(&epk_y)?;

        let mut ctx = BigNumContext::new()?;
        point.set_affine_coordinates_gfp(&group, &epk_x, &epk_y, &mut ctx)?;

        let epk = EcKey::from_public_key(&group, &point)?;
        let epk = PKey::from_ec_key(epk)?;
        match wrapping_algorithm {
            KeyWrapAlgorithm::EcdhEsA256Kw => {
                let mut deriver = Deriver::new(self.private_key())?;
                deriver.set_peer(&epk)?;
                let z = deriver.derive_to_vec()?;
                let shared_key = concat_kdf(
                    KeyWrapAlgorithm::EcdhEsA256Kw.as_ref(),
                    AES_GCM_256_KEY_BITS as usize / 8,
                    &z,
                )?;
                let mut key = vec![0; encrypted_key.len() - 8];
                let unwrapping_key = AesKey::new_decrypt(&shared_key)
                    .map_err(|e| anyhow!("failed to create AES unwrapping key: {e:?}"))?;
                aes::unwrap_key(&unwrapping_key, None, &mut key, &encrypted_key)
                    .map_err(|e| anyhow!("failed to unwrap key: {e:?}"))?;
                Ok(key)
            }
        }
    }
}

fn concat_kdf(alg: &str, target_length: usize, z: &[u8]) -> Result<Vec<u8>> {
    let target_length_bytes = ((target_length * 8) as u32).to_be_bytes();
    let alg_len_bytes = (alg.len() as u32).to_be_bytes();

    let mut output = Vec::new();
    let md = MessageDigest::sha256();
    let count = target_length.div_ceil(md.size());
    for i in 0..count {
        let mut hasher = Hasher::new(md)?;
        hasher.update(&((i + 1) as u32).to_be_bytes())?;
        hasher.update(z)?;
        hasher.update(&alg_len_bytes)?;
        hasher.update(alg.as_bytes())?;
        hasher.update(&0_u32.to_be_bytes())?;
        hasher.update(&0_u32.to_be_bytes())?;
        hasher.update(&target_length_bytes)?;

        let digest = hasher.finish()?;
        output.extend(digest.to_vec());
    }

    if output.len() > target_length {
        output.truncate(target_length);
    }

    Ok(output)
}

#[derive(Clone, Debug)]
pub struct P256EcKeyPair {
    private_key: PKey<Private>,
}

impl Default for P256EcKeyPair {
    fn default() -> Self {
        Self::new().expect("Create P256 key pair failed")
    }
}

impl P256EcKeyPair {
    fn private_key(&self) -> &PKey<Private> {
        &self.private_key
    }

    pub fn new() -> Result<Self> {
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&ec_group)?;
        let private_key = PKey::from_ec_key(ec_key)?;
        Ok(Self { private_key })
    }

    pub fn x(&self) -> Result<Vec<u8>> {
        let private_key = self.private_key.ec_key().context("must be a ec key")?;
        let public_key = private_key.public_key();
        let mut x = BigNum::new()?;
        let mut _y = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        public_key.affine_coordinates_gfp(private_key.group(), &mut x, &mut _y, &mut ctx)?;
        let mut x = x.to_vec();
        x.resize(32, b'0');
        Ok(x)
    }

    pub fn y(&self) -> Result<Vec<u8>> {
        let private_key = self.private_key.ec_key().context("must be a ec key")?;
        let public_key = private_key.public_key();
        let mut _x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        public_key.affine_coordinates_gfp(private_key.group(), &mut _x, &mut y, &mut ctx)?;
        let mut y = y.to_vec();
        y.resize(32, b'0');
        Ok(y)
    }
}
