// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::{
    ec::{EcKeyPair, KeyWrapAlgorithm, P256EcKeyPair, P521EcKeyPair},
    rsa::{PaddingMode, RSAKeyPair},
};
use kbs_types::{ProtectedHeader, Response, TeePubKey};
use tracing::warn;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct TeeKeyPair {
    key: TeeKey,
}

#[derive(Clone, Debug)]
pub enum TeeKey {
    Rsa(Box<RSAKeyPair>),
    Ec(Box<EcKeyPair>),
}

#[derive(Clone, Copy, Debug, Default)]
pub enum TeeKeyAlgorithm {
    #[default]
    EcdhEsA256KwP256,
    EcdhEsA256KwP521,
    RsaOaep256,
}

impl TeeKeyPair {
    /// Create a new Tee key pair. We by default to use EC key pair.
    pub fn new() -> Result<Self> {
        Self::new_with_algorithm(TeeKeyAlgorithm::default())
    }

    pub fn new_with_algorithm(algo: TeeKeyAlgorithm) -> Result<Self> {
        let key = match algo {
            TeeKeyAlgorithm::EcdhEsA256KwP256 => {
                TeeKey::Ec(Box::new(EcKeyPair::P256(P256EcKeyPair::default())))
            }
            TeeKeyAlgorithm::EcdhEsA256KwP521 => {
                TeeKey::Ec(Box::new(EcKeyPair::P521(P521EcKeyPair::default())))
            }
            TeeKeyAlgorithm::RsaOaep256 => TeeKey::Rsa(Box::new(RSAKeyPair::new()?)),
        };
        Ok(Self { key })
    }

    /// Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        match &self.key {
            TeeKey::Rsa(key) => {
                let k_mod = URL_SAFE_NO_PAD.encode(key.n());
                let k_exp = URL_SAFE_NO_PAD.encode(key.e());

                Ok(TeePubKey::RSA {
                    alg: PaddingMode::OAEP.as_ref().to_string(),
                    k_mod,
                    k_exp,
                })
            }
            TeeKey::Ec(key) => {
                let x = URL_SAFE_NO_PAD.encode(key.x()?);
                let y = URL_SAFE_NO_PAD.encode(key.y()?);

                Ok(TeePubKey::EC {
                    crv: key.curve().as_ref().to_string(),
                    alg: KeyWrapAlgorithm::EcdhEsA256Kw.as_ref().to_string(),
                    x,
                    y,
                })
            }
        }
    }

    #[inline]
    pub fn unwrap_cek(&self, header: &ProtectedHeader, wrapped_cek: Vec<u8>) -> Result<Vec<u8>> {
        #[allow(deprecated)]
        if &header.alg[..] == PaddingMode::PKCS1v15.as_ref() {
            warn!("Use deprecated Rsa PKCSv1.5 algorithm!");
            let TeeKey::Rsa(key) = &self.key else {
                bail!("Unmatched key. Must be RSA key");
            };

            let cek = key.decrypt(PaddingMode::PKCS1v15, wrapped_cek)?;
            Ok(cek)
        } else if &header.alg[..] == PaddingMode::OAEP.as_ref() {
            let TeeKey::Rsa(key) = &self.key else {
                bail!("Unmatched key. Must be RSA key");
            };

            let cek = key.decrypt(PaddingMode::OAEP, wrapped_cek)?;
            Ok(cek)
        } else if &header.alg[..] == KeyWrapAlgorithm::EcdhEsA256Kw.as_ref() {
            let epk = header
                .other_fields
                .get("epk")
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. Without `epk`"))?;
            let crv = epk
                .get("crv")
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. Without `crv`"))?
                .as_str()
                .ok_or(anyhow!(
                    "Invalid JWE ProtectedHeader. `crv` is not a string"
                ))?;

            let x = epk
                .get("x")
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. Without `x`"))?
                .as_str()
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. `x` is not a string"))?;

            let x = URL_SAFE_NO_PAD.decode(x)?;

            let y = epk
                .get("y")
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. Without `y`"))?
                .as_str()
                .ok_or(anyhow!("Invalid JWE ProtectedHeader. `y` is not a string"))?;

            let y = URL_SAFE_NO_PAD.decode(y)?;

            let TeeKey::Ec(key) = &self.key else {
                bail!("Unmatched key. Must be EC key");
            };

            if crv != key.curve().as_ref() {
                bail!("Unmatched curve: {}", crv);
            }

            let cek = key.unwrap_key(wrapped_cek, x, y, KeyWrapAlgorithm::EcdhEsA256Kw)?;
            Ok(cek)
        } else {
            bail!("Unsupported algorithm: {}", header.alg)
        }
    }

    #[inline]
    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(keypair) = RSAKeyPair::from_pkcs1_pem(pem) {
            return Ok(Self {
                key: TeeKey::Rsa(Box::new(keypair)),
            });
        }

        let keypair = EcKeyPair::from_pkcs8_pem(pem)
            .context("private key is not RSA (PKCS#1) nor EC P256/P521 (PKCS#8)")?;
        Ok(Self {
            key: TeeKey::Ec(Box::new(keypair)),
        })
    }

    #[inline]
    pub fn to_pem(&self) -> Result<Zeroizing<String>> {
        match &self.key {
            TeeKey::Rsa(keypair) => keypair.to_pkcs1_pem(),
            TeeKey::Ec(keypair) => keypair.to_pkcs8_pem(),
        }
    }

    pub fn decrypt_response(&self, response: Response) -> Result<Vec<u8>> {
        // unwrap the wrapped key
        let cek = self.unwrap_cek(&response.protected, response.encrypted_key)?;

        let aad = response.protected.generate_aad()?;
        let plaintext = crypto::decrypt_aead(
            Zeroizing::new(cek),
            response.ciphertext,
            response.iv,
            aad,
            response.tag,
            crypto::WrapType::Aes256Gcm,
        )?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_to_p256() {
        let keypair = TeeKeyPair::new().expect("new keypair");
        let TeePubKey::EC { crv, .. } = keypair.export_pubkey().expect("export key") else {
            panic!("must be ec key")
        };
        assert_eq!(crv, "P-256");
    }

    #[test]
    fn new_with_p521_exports_p521() {
        let keypair =
            TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::EcdhEsA256KwP521).expect("new keypair");
        let TeePubKey::EC { crv, .. } = keypair.export_pubkey().expect("export key") else {
            panic!("must be ec key")
        };
        assert_eq!(crv, "P-521");
    }

    #[test]
    fn new_with_rsa_exports_rsa_oaep() {
        let keypair =
            TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::RsaOaep256).expect("new keypair");
        let TeePubKey::RSA { alg, .. } = keypair.export_pubkey().expect("export key") else {
            panic!("must be rsa key")
        };
        assert_eq!(alg, "RSA-OAEP-256");
    }
}
