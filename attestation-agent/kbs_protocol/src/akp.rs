// Copyright (c) 2026 Arqit / guest-components contributors.
// SPDX-License-Identifier: Apache-2.0

//! Experimental Post-Quantum KEM support for the KBS resource-response JWE
//! path, client side.
//!
//! Implements the decryption half of `ML-KEM-768+A192KW` per
//! draft-ietf-jose-pqc-kem-05. Counterpart of the server-side
//! `kbs/src/akp.rs` in the trustee repo.
//!
//! Wire format is not finalized — the IETF draft is WG-adopted Standards
//! Track but not yet RFC. The KDF FixedInfo encoding (X input to KMAC256)
//! is underspecified by the draft; we follow the RFC 7518 §4.6.2 ConcatKDF
//! precedent, omitting PartyUInfo/PartyVInfo as the PQ draft directs. This
//! MUST stay byte-identical to the server's `kmac256_kdf` or AES-KW unwrap
//! will fail. Re-validate against reference implementations and test
//! vectors when those emerge.

use aes_kw::{KeyInit, KwAes192};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::TeePubKey;
use ml_kem::{kem::KeyExport, Decapsulate, DecapsulationKey, EncapsulationKey, Kem, MlKem768};
use sha3_kmac::Kmac256;

/// `kty` value for the Algorithm Key Pair (AKP) key type per
/// draft-ietf-jose-pqc-kem-05 §10.
pub const AKP_KTY: &str = "AKP";

/// Algorithm identifier for ML-KEM-768 with AES-192 key wrap.
pub const ML_KEM_768_A192KW_ALGORITHM: &str = "ML-KEM-768+A192KW";

/// AES-192 wrap-key length in bytes (= 192 bits ÷ 8). Per
/// draft-ietf-jose-pqc-kem-05 §8 the wrap variant for ML-KEM-768 is A192KW.
const A192KW_KEY_LEN: usize = 24;

/// AES-256 content-encryption-key length in bytes. Matches the existing
/// classical paths' `A256GCM`.
const A256_CEK_LEN: usize = 32;

/// ML-KEM-768 keypair held by the TEE for the resource-response JWE path.
///
/// `Clone` is required because `TeeKey` and `TeeKeyPair` derive `Clone`.
/// `Debug` is implemented manually to avoid leaking the decapsulation key.
#[derive(Clone)]
pub struct AkpKeyPair {
    encap_key: EncapsulationKey<MlKem768>,
    decap_key: DecapsulationKey<MlKem768>,
}

impl std::fmt::Debug for AkpKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AkpKeyPair").finish_non_exhaustive()
    }
}

impl AkpKeyPair {
    /// Generate a fresh ML-KEM-768 keypair. Uses OS RNG internally via
    /// `ml-kem`'s `getrandom` feature.
    pub fn generate() -> Self {
        let (decap_key, encap_key) = MlKem768::generate_keypair();
        Self {
            encap_key,
            decap_key,
        }
    }

    /// Raw encapsulation-key bytes (1184 bytes for ML-KEM-768) suitable for
    /// base64url encoding in the JWK `pub` field.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.encap_key.to_bytes().to_vec()
    }

    /// Build the JWK wire representation of this keypair's public key.
    pub fn to_pub_jwk(&self) -> TeePubKey {
        TeePubKey::AKP {
            alg: ML_KEM_768_A192KW_ALGORITHM.to_string(),
            public_key: URL_SAFE_NO_PAD.encode(self.public_key_bytes()),
        }
    }

    /// Decapsulate the KEM ciphertext (`ek` JOSE header) and AES-KW-unwrap
    /// the content-encryption key.
    ///
    /// `kem_ciphertext`: raw bytes from the JWE `ek` header
    /// (already base64url-decoded).
    /// `wrapped_cek`: bytes from the JWE `encrypted_key` field.
    ///
    /// Returns the 32-byte CEK ready for AES-256-GCM payload decryption.
    pub fn decapsulate_and_unwrap(
        &self,
        kem_ciphertext: &[u8],
        wrapped_cek: &[u8],
    ) -> Result<Vec<u8>> {
        let shared_secret = self
            .decap_key
            .decapsulate_slice(kem_ciphertext)
            .map_err(|e| anyhow!("ML-KEM-768 decapsulate failed: {e:?}"))?;

        let kwk = kmac256_kdf(
            shared_secret.as_slice(),
            ML_KEM_768_A192KW_ALGORITHM,
            A192KW_KEY_LEN,
        )?;
        let kwk: [u8; A192KW_KEY_LEN] = kwk
            .try_into()
            .map_err(|_| anyhow!("KDF output not {A192KW_KEY_LEN} bytes"))?;

        let unwrapper =
            KwAes192::new_from_slice(&kwk).map_err(|e| anyhow!("AES-KW key init failed: {e:?}"))?;
        let mut cek = vec![0u8; A256_CEK_LEN];
        unwrapper
            .unwrap_key(wrapped_cek, &mut cek)
            .map_err(|e| anyhow!("AES-KW unwrap failed: {e:?}"))?;
        Ok(cek)
    }
}

/// KMAC256-based KDF per draft-ietf-jose-pqc-kem-05 §5.1.
///
/// `KMAC256(K = shared_secret, X = AlgorithmID || SuppPubInfo,
///          L = out_len_bytes·8 bits, S = "")`
///
/// AlgorithmID = 4-byte BE length(alg) || alg.
/// SuppPubInfo = 4-byte BE keydatalen-in-bits.
/// PartyUInfo / PartyVInfo are intentionally excluded per the draft.
///
/// MUST stay byte-identical to the server's `kbs/src/akp.rs::kmac256_kdf`.
///
/// Visible to the rest of the crate to support unwrap-path testing in
/// `keypair.rs` without re-implementing the encoding.
pub(crate) fn kmac256_kdf(
    shared_secret: &[u8],
    alg: &str,
    out_len_bytes: usize,
) -> Result<Vec<u8>> {
    let alg_bytes = alg.as_bytes();
    let alg_len = (alg_bytes.len() as u32).to_be_bytes();
    let keydatalen_bits = ((out_len_bytes * 8) as u32).to_be_bytes();

    let mut x = Vec::with_capacity(4 + alg_bytes.len() + 4);
    x.extend_from_slice(&alg_len);
    x.extend_from_slice(alg_bytes);
    x.extend_from_slice(&keydatalen_bits);

    let mut kmac =
        Kmac256::new(shared_secret, b"").map_err(|e| anyhow!("KMAC256 init failed: {e:?}"))?;
    kmac.update(&x);
    let mut out = vec![0u8; out_len_bytes];
    kmac.finalize_into(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::Encapsulate;

    /// End-to-end roundtrip: encapsulate to the keypair's own public key,
    /// derive the KWK via the same KDF, wrap a known CEK, then exercise
    /// the client-side `decapsulate_and_unwrap` and confirm the CEK
    /// matches. This verifies the KDF + AES-KW + ML-KEM decapsulation
    /// codepath end-to-end without depending on the server.
    #[test]
    fn decapsulate_and_unwrap_roundtrip() {
        let keypair = AkpKeyPair::generate();

        let (kem_ciphertext, shared_secret) = keypair.encap_key.encapsulate();

        let kwk =
            kmac256_kdf(shared_secret.as_slice(), ML_KEM_768_A192KW_ALGORITHM, 24).expect("kdf");
        let kwk: [u8; 24] = kwk.try_into().unwrap();

        let cek_orig: [u8; 32] = [7u8; 32];
        let wrapper = KwAes192::new_from_slice(&kwk).expect("init KWK");
        let mut wrapped_cek = vec![0u8; 40]; // 32-byte CEK + 8-byte AES-KW integrity check
        wrapper
            .wrap_key(&cek_orig, &mut wrapped_cek)
            .expect("wrap CEK");

        let cek_recovered = keypair
            .decapsulate_and_unwrap(kem_ciphertext.as_slice(), &wrapped_cek)
            .expect("decapsulate_and_unwrap");

        assert_eq!(cek_recovered.as_slice(), &cek_orig[..]);
    }

    #[test]
    fn pub_jwk_has_correct_fields_and_length() {
        let kp = AkpKeyPair::generate();
        let TeePubKey::AKP { alg, public_key } = kp.to_pub_jwk() else {
            panic!("expected AKP variant");
        };
        assert_eq!(alg, ML_KEM_768_A192KW_ALGORITHM);
        let bytes = URL_SAFE_NO_PAD.decode(&public_key).expect("base64");
        assert_eq!(bytes.len(), 1184); // ML-KEM-768 encap-key length per FIPS 203.
    }

    #[test]
    fn kdf_is_deterministic_and_correct_length() {
        let secret = [0u8; 32];
        let out = kmac256_kdf(&secret, ML_KEM_768_A192KW_ALGORITHM, 24).expect("kdf");
        assert_eq!(out.len(), 24);
        let out2 = kmac256_kdf(&secret, ML_KEM_768_A192KW_ALGORITHM, 24).expect("kdf again");
        assert_eq!(out, out2);
    }
}
