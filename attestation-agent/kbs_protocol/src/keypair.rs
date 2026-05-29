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
use serde::Deserialize;
use tracing::warn;
use zeroize::Zeroizing;

#[cfg(feature = "pqc-experimental")]
use crate::akp::{AkpKeyPair, ML_KEM_768_A192KW_ALGORITHM};

#[derive(Clone, Debug)]
pub struct TeeKeyPair {
    key: TeeKey,
}

#[derive(Clone, Debug)]
pub enum TeeKey {
    Rsa(Box<RSAKeyPair>),
    Ec(Box<EcKeyPair>),
    /// ML-KEM-768 keypair for the experimental Post-Quantum KEM path.
    /// See [`crate::akp`] and `pqc_kbs_direction` memory.
    #[cfg(feature = "pqc-experimental")]
    Akp(Box<AkpKeyPair>),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum TeeKeyAlgorithm {
    #[default]
    #[serde(rename = "ECDH-ES+A256KW-P256")]
    EcdhEsA256KwP256,
    #[serde(rename = "ECDH-ES+A256KW-P521")]
    EcdhEsA256KwP521,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// ML-KEM-768 with AES-192 key wrap per draft-ietf-jose-pqc-kem-05.
    /// Gated behind `pqc-experimental`; default-build configs cannot select
    /// this variant.
    #[cfg(feature = "pqc-experimental")]
    #[serde(rename = "ML-KEM-768+A192KW")]
    MlKem768A192Kw,
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
            #[cfg(feature = "pqc-experimental")]
            TeeKeyAlgorithm::MlKem768A192Kw => TeeKey::Akp(Box::new(AkpKeyPair::generate())),
        };
        Ok(Self { key })
    }

    /// Whether this keypair uses the experimental AKP (ML-KEM-768) algorithm.
    ///
    /// Always `false` when the `pqc-experimental` Cargo feature is off, so
    /// callers can use this unconditionally without their own feature gate.
    pub fn is_akp(&self) -> bool {
        #[cfg(feature = "pqc-experimental")]
        {
            matches!(&self.key, TeeKey::Akp(_))
        }
        #[cfg(not(feature = "pqc-experimental"))]
        {
            false
        }
    }

    /// Export TEE public key as a typed `kbs_types::TeePubKey`.
    ///
    /// Returns an error for AKP variants — the upstream `TeePubKey` enum has
    /// no AKP variant (kbs-types 0.15.0). Callers in the AKP path should use
    /// [`Self::export_pubkey_value`] instead, which returns a
    /// `serde_json::Value` and bypasses the typed enum.
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
            #[cfg(feature = "pqc-experimental")]
            TeeKey::Akp(_) => bail!(
                "export_pubkey() cannot represent AKP; use export_pubkey_value() instead"
            ),
        }
    }

    /// Export TEE public key as a `serde_json::Value`.
    ///
    /// Used by the AKP wire path, which embeds a JWK that the upstream
    /// `kbs_types::TeePubKey` enum can't represent. For classical (RSA/EC)
    /// keys this is just `serde_json::to_value(self.export_pubkey()?)`.
    pub fn export_pubkey_value(&self) -> Result<serde_json::Value> {
        match &self.key {
            #[cfg(feature = "pqc-experimental")]
            TeeKey::Akp(key) => serde_json::to_value(key.to_pub_jwk())
                .context("serialize AkpPubKey to JSON"),
            _ => serde_json::to_value(self.export_pubkey()?)
                .context("serialize TeePubKey to JSON"),
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
            #[cfg(feature = "pqc-experimental")]
            if header.alg == ML_KEM_768_A192KW_ALGORITHM {
                let ek_b64 = header
                    .other_fields
                    .get("ek")
                    .ok_or(anyhow!("Invalid JWE ProtectedHeader. Without `ek`"))?
                    .as_str()
                    .ok_or(anyhow!(
                        "Invalid JWE ProtectedHeader. `ek` is not a string"
                    ))?;

                let kem_ciphertext = URL_SAFE_NO_PAD
                    .decode(ek_b64)
                    .context("base64url decode `ek` failed")?;

                let TeeKey::Akp(key) = &self.key else {
                    bail!("Unmatched key. Must be AKP key");
                };

                return key.decapsulate_and_unwrap(&kem_ciphertext, &wrapped_cek);
            }

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
            #[cfg(feature = "pqc-experimental")]
            TeeKey::Akp(_) => bail!("PEM serialization is not supported for AKP keys"),
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

    #[test]
    fn deserialize_jwa_compact_algorithms() {
        let p256: TeeKeyAlgorithm = serde_json::from_str("\"ECDH-ES+A256KW-P256\"")
            .expect("ECDH-ES+A256KW-P256 algorithm should parse");
        assert_eq!(p256, TeeKeyAlgorithm::EcdhEsA256KwP256);

        let p521: TeeKeyAlgorithm = serde_json::from_str("\"ECDH-ES+A256KW-P521\"")
            .expect("ECDH-ES+A256KW-P521 algorithm should parse");
        assert_eq!(p521, TeeKeyAlgorithm::EcdhEsA256KwP521);

        let rsa_oaep256: TeeKeyAlgorithm =
            serde_json::from_str("\"RSA-OAEP-256\"").expect("RSA-OAEP-256 algorithm should parse");
        assert_eq!(rsa_oaep256, TeeKeyAlgorithm::RsaOaep256);
    }
}

#[cfg(all(test, feature = "pqc-experimental"))]
mod pqc_tests {
    use super::*;
    use crate::akp::{kmac256_kdf, ML_KEM_768_A192KW_ALGORITHM};
    use aes_kw::KekAes192;
    use ml_kem::{Encapsulate, EncapsulationKey, Key, MlKem768};

    #[test]
    fn deserialize_ml_kem_algorithm() {
        let algo: TeeKeyAlgorithm = serde_json::from_str("\"ML-KEM-768+A192KW\"")
            .expect("ML-KEM-768+A192KW algorithm should parse");
        assert_eq!(algo, TeeKeyAlgorithm::MlKem768A192Kw);
    }

    #[test]
    fn new_with_akp_exports_akp_jwk() {
        let keypair = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::MlKem768A192Kw)
            .expect("new AKP keypair");
        let value = keypair
            .export_pubkey_value()
            .expect("export pubkey value");
        assert_eq!(value["kty"], "AKP");
        assert_eq!(value["alg"], ML_KEM_768_A192KW_ALGORITHM);
        // Encap key is 1184 bytes → base64url with no padding is 1579 chars.
        assert_eq!(value["pub"].as_str().expect("pub field").len(), 1579);
    }

    #[test]
    fn export_pubkey_errors_for_akp() {
        let keypair = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::MlKem768A192Kw)
            .expect("new AKP keypair");
        let err = keypair
            .export_pubkey()
            .expect_err("AKP must not round-trip through TeePubKey");
        assert!(err.to_string().contains("AKP"));
    }

    #[test]
    fn to_pem_errors_for_akp() {
        let keypair = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::MlKem768A192Kw)
            .expect("new AKP keypair");
        let err = keypair.to_pem().expect_err("AKP has no PEM format in phase 1");
        assert!(err.to_string().contains("AKP"));
    }

    /// Build a `ProtectedHeader` + wrapped CEK as the server would emit
    /// (encapsulate to our pubkey, derive KWK via the shared KDF, AES-KW
    /// wrap a known CEK, base64url the KEM ciphertext into `ek`), then
    /// confirm `TeeKeyPair::unwrap_cek` returns the same CEK. Exercises
    /// the new AKP arm in `unwrap_cek` end-to-end.
    #[test]
    fn unwrap_cek_for_ml_kem_response() {
        let keypair = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::MlKem768A192Kw)
            .expect("new AKP keypair");
        let TeeKey::Akp(akp_keypair) = &keypair.key else {
            panic!("expected AKP variant");
        };

        // Simulate the server: parse our own public key as an encap key.
        let pub_bytes = akp_keypair.public_key_bytes();
        let ek_typed: &Key<EncapsulationKey<MlKem768>> =
            pub_bytes.as_slice().try_into().unwrap();
        let encap_key = EncapsulationKey::<MlKem768>::new(ek_typed).unwrap();
        let (kem_ciphertext, shared_secret) = encap_key.encapsulate();

        // Same KDF the client side uses on decrypt — guarantees the wrap
        // key matches.
        let kwk =
            kmac256_kdf(shared_secret.as_slice(), ML_KEM_768_A192KW_ALGORITHM, 24).unwrap();
        let kwk: [u8; 24] = kwk.try_into().unwrap();

        // Wrap a known CEK.
        let cek_orig: [u8; 32] = [0xAB; 32];
        let wrapper = KekAes192::from(kwk);
        let mut wrapped_cek = vec![0u8; 40];
        wrapper.wrap(&cek_orig, &mut wrapped_cek).unwrap();

        // Build the ProtectedHeader as the server emits.
        let ek_b64 = URL_SAFE_NO_PAD.encode(kem_ciphertext.as_slice());
        let header = ProtectedHeader {
            alg: ML_KEM_768_A192KW_ALGORITHM.to_string(),
            enc: "A256GCM".to_string(),
            other_fields: serde_json::json!({ "ek": ek_b64 })
                .as_object()
                .unwrap()
                .clone(),
        };

        let cek = keypair.unwrap_cek(&header, wrapped_cek).expect("unwrap CEK");
        assert_eq!(cek.as_slice(), &cek_orig[..]);
    }
}
