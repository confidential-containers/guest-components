// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fmt;
use std::io;
use std::io::ErrorKind;

use anyhow::anyhow;

use aes_gcm::aead::rand_core::{OsRng, RngCore};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};

use super::StreamProcessor;

pub struct AesGcmProcessor {
    input_cipher: Aes256Gcm,
    output_cipher: Aes256Gcm,
    input_counter: u32, // counters are mutable and assume the sender starts at 1
    output_counter: u32,
}

const MAGIC: [u8; 4] = [0xD1, 0xA2, 0xE3, 0xB4];

impl AesGcmProcessor {
    pub fn new(in_key: Vec<u8>, out_key: Vec<u8>) -> Result<Self, std::io::Error> {
        let in_key: [u8; 32] = in_key
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "gcm key must be 32 bytes"))?;
        let key_in = Key::<Aes256Gcm>::from_slice(&in_key);
        let input_cipher = Aes256Gcm::new(&key_in);

        let out_key: [u8; 32] = out_key
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "key must be 32 bytes"))?;
        let out_key = Key::<Aes256Gcm>::from_slice(&out_key);
        let output_cipher = Aes256Gcm::new(&out_key);

        Ok(Self {
            input_cipher,
            output_cipher,
            input_counter: 0,
            output_counter: 1,
        })
    }
}

impl StreamProcessor for AesGcmProcessor {
    fn process_input(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // do_write_stream() -> Decrypt
        //
        // Wire format (one or more frames):
        //   header(8B): length(4B BE) | seq(4B BE)  — used as AAD
        //   frame body: nonce(12B: random(8B) | seq(4B BE)) | ciphertext+tag

        let mut offset = 0;
        let mut output = Vec::new();

        while offset < data.len() {
            // --- read 8-byte header ---
            if offset + 8 > data.len() {
                // eprintln!("stream_processor: gcm incomplete header");
                return Err(anyhow!("stream_processor: gcm incomplete header"));
            }
            let header: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
            let frame_len = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
            let seq = u32::from_be_bytes(header[4..8].try_into().unwrap());
            offset += 8;

            // Pre-crypto replay / reorder detection.
            if seq <= self.input_counter {
                return Err(anyhow!(
                    "stream_processor: gcm replay/reorder seq={} last={}",
                    seq,
                    self.input_counter
                ));
            }

            // --- read frame body (nonce + ciphertext+tag) ---
            if offset + frame_len > data.len() {
                // eprintln!("stream_processor: gcm incomplete frame body");
                return Err(anyhow!("stream_processor: gcm incomplete frame body"));
            }
            let frame = &data[offset..offset + frame_len];
            offset += frame_len;

            if frame.len() < 12 {
                return Err(anyhow!("stream_processor: gcm frame too small"));
            }

            let nonce_bytes = &frame[..12];
            let ciphertext = &frame[12..];

            // Cross-check: nonce[8:12] must carry the same seq as the header.
            let nonce_seq = u32::from_be_bytes(nonce_bytes[8..12].try_into().unwrap());
            if nonce_seq != seq {
                return Err(anyhow!(
                    "stream_processor: gcm nonce/seq mismatch header_seq={} nonce_seq={}",
                    seq,
                    nonce_seq
                ));
            }

            self.input_counter = seq;

            let nonce = GenericArray::from_slice(nonce_bytes);
            let plaintext = self
                .input_cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &header,
                    },
                )
                .map_err(|e| {
                    anyhow!(
                        "stream_processor: gcm decryption failed (seq={}): {:?}",
                        seq,
                        e
                    )
                })?;

            output.extend_from_slice(&plaintext);
        }

        Ok(output)
    }

    fn process_output(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // do_read_stream() -> Encrypt, writing to the client.
        //
        // Wire format emitted:
        //   magic(4B) | header(8B: length(4B BE) | seq(4B BE)) | nonce(12B) | ciphertext+tag
        //   header is used as AAD.

        let seq = self.output_counter;
        self.output_counter = self
            .output_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("stream_processor: gcm output counter overflow"))?;

        // Build nonce: 8 random bytes || seq (4B BE).
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes[..8]);
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Build header (AAD): length(4B BE) | seq(4B BE).
        // length = nonce(12) + plaintext.len() + tag(16)
        let payload_len = (12 + data.len() + 16) as u32;
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&payload_len.to_be_bytes());
        header[4..8].copy_from_slice(&seq.to_be_bytes());

        let ciphertext = self
            .output_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &header,
                },
            )
            .map_err(|e| {
                anyhow!(
                    "stream_processor: gcm encryption failed (seq={}): {:?}",
                    seq,
                    e
                )
            })?;

        // Emit: magic(4B) | header(8B) | nonce(12B) | ciphertext+tag
        // Note: any changes to the frame size must be reflected in agent's rpc.rs, see do_read_stream()
        let mut output = Vec::with_capacity(4 + 8 + 12 + ciphertext.len());
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&header);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }
}

impl fmt::Debug for AesGcmProcessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmProcessor")
            .field("input_cipher", &"<hidden>")
            .field("output_cipher", &"<hidden>")
            .finish()
    }
}
