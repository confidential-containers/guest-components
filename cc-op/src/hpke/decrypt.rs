// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};

use hpke::{
    aead::{AeadCtxR, AesGcm256},
    kdf::HkdfSha256,
    kem::DhP256HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR,
};

use p256::{
    elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};

#[derive(Debug)]
pub struct AAD {
    pub version: u8,
    pub name_space: String,
    pub pod_name: String,
    pub container_name: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ChannelKeys {
    pub encrypt_key: Vec<u8>, // 32 bytes for AES-256
    pub decrypt_key: Vec<u8>, // 32 bytes for AES-256
}

// Type aliases for HPKE configuration (P-256, HKDF-SHA256, AES-256-GCM)
type Kem = DhP256HkdfSha256;
type Kdf = HkdfSha256;
type Aead = AesGcm256;

pub fn encode_aad(a: &AAD) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.push(a.version);
    // Max string len: 65535 byte
    // NameSpace
    buf.write_u16::<BigEndian>(a.name_space.len() as u16)
        .unwrap();
    buf.extend_from_slice(a.name_space.as_bytes());

    // PodName
    buf.write_u16::<BigEndian>(a.pod_name.len() as u16).unwrap();
    buf.extend_from_slice(a.pod_name.as_bytes());

    // ContainerName
    buf.write_u16::<BigEndian>(a.container_name.len() as u16)
        .unwrap();
    buf.extend_from_slice(a.container_name.as_bytes());

    // Timestamp
    buf.write_u64::<BigEndian>(a.timestamp).unwrap();

    buf
}

/// HPKE Authenticated Decryption with Context
/// Port of HPKEAuthDecryptWithContext
///
/// Performs HPKE authenticated decryption and returns the plaintext and an opener
/// context that can be used for key derivation.
pub fn hpke_auth_decrypt_with_context(
    receiver_private_key: &P256SecretKey,
    sender_public_key: &P256PublicKey,
    encapsulated_key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, AeadCtxR<Aead, Kdf, Kem>)> {
    // Convert P256 keys to HPKE KEM format
    let receiver_sk_bytes = receiver_private_key.to_bytes();
    let receiver_hpke_sk = <Kem as KemTrait>::PrivateKey::from_bytes(&receiver_sk_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to convert receiver private key to HPKE format"))?;

    // Convert sender public key to uncompressed point format
    let sender_pk_point = sender_public_key.to_encoded_point(false);
    let sender_hpke_pk = <Kem as KemTrait>::PublicKey::from_bytes(sender_pk_point.as_bytes())
        .map_err(|_| anyhow::anyhow!("Failed to convert sender public key to HPKE format"))?;

    // Deserialize the encapsulated key
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|_| anyhow::anyhow!("Failed to deserialize encapsulated key"))?;

    // Setup authenticated receiver context
    let mut opener = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Auth(sender_hpke_pk),
        &receiver_hpke_sk,
        &encapped_key,
        info,
    )
    .map_err(|e| anyhow::anyhow!("Failed to setup auth receiver: {:?}", e))?;

    // Decrypt and verify the ciphertext
    let plaintext = opener.open(ciphertext, aad).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open ciphertext (decryption/verification failed): {:?}",
            e
        )
    })?;

    Ok((plaintext, opener))
}

/// Derive channel keys from HPKE opener context
/// Port of DeriveChannelKeysFromOpener
///
pub fn derive_channel_keys_from_opener(
    opener: &mut AeadCtxR<Aead, Kdf, Kem>,
) -> Result<ChannelKeys> {
    // Export keys using the same context strings as the sender
    // Receiver swaps the operations:
    // - What sender calls "encrypt" is what receiver uses to "decrypt"
    // - What sender calls "decrypt" is what receiver uses to "encrypt"

    let mut encrypt_key = vec![0u8; 32];
    opener
        .export(b"channel-decrypt-key", &mut encrypt_key)
        .map_err(|e| anyhow::anyhow!("Failed to export encrypt key: {:?}", e))?;

    let mut decrypt_key = vec![0u8; 32];
    opener
        .export(b"channel-encrypt-key", &mut decrypt_key)
        .map_err(|e| anyhow::anyhow!("Failed to export decrypt key: {:?}", e))?;

    Ok(ChannelKeys {
        encrypt_key,
        decrypt_key,
    })
}
