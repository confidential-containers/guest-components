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
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};

use super::StreamProcessor;

pub struct AesGcmTtyProcessor {
    /// Decrypts frames arriving from the remote peer (input direction).
    input_cipher: Aes256Gcm,
    /// Encrypts frames sent to the remote peer (output direction).
    output_cipher: Aes256Gcm,
    /// Monotonically increasing counter for frames we have received.
    /// Starts at 0; the first accepted counter value is 1.
    input_counter: u32,
    /// Monotonically increasing counter for frames we send.
    /// Starts at 1.
    output_counter: u32,
    /// Reassembly buffer for partial frames arriving across multiple RPCs.
    input_buf: Vec<u8>,
}

impl AesGcmTtyProcessor {
    pub fn new(in_key: Vec<u8>, out_key: Vec<u8>) -> Result<Self, io::Error> {
        let in_key: [u8; 32] = in_key.as_slice().try_into().map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "gcmtty in_key must be 32 bytes")
        })?;
        let key_in = Key::<Aes256Gcm>::from_slice(&in_key);
        let input_cipher = Aes256Gcm::new(key_in);

        let out_key: [u8; 32] = out_key.as_slice().try_into().map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "gcmtty out_key must be 32 bytes")
        })?;
        let key_out = Key::<Aes256Gcm>::from_slice(&out_key);
        let output_cipher = Aes256Gcm::new(key_out);

        Ok(Self {
            input_cipher,
            output_cipher,
            input_counter: 0,
            output_counter: 1,
            input_buf: Vec::new(),
        })
    }

    /// Build the 8-byte header: length(4B) || seq(4B).
    /// `payload_len` = nonce(12) + ciphertext+tag(plain+16).
    fn make_header(payload_len: u32, seq: u32) -> [u8; 8] {
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&payload_len.to_be_bytes());
        hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        hdr
    }
}

impl StreamProcessor for AesGcmTtyProcessor {
    /// Decrypt all complete frames from the incoming byte stream.
    ///
    /// Bytes are appended to an internal reassembly buffer so that frames
    /// split across multiple WriteStreamRequest RPCs are handled correctly.
    /// Only verified, decrypted plaintext from complete frames is returned;
    /// partial trailing bytes are held for the next call.
    ///
    /// Frame layout expected:
    ///   header(8B: length 4B + seq 4B) || nonce(12B) || ciphertext+tag
    fn process_input(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.input_buf.extend_from_slice(data);

        let mut output = Vec::new();

        loop {
            let buf = &self.input_buf;

            // Need at least 8 bytes for the header.
            if buf.len() < 8 {
                break;
            }

            let length = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            let seq = u32::from_be_bytes(buf[4..8].try_into().unwrap());

            // length must cover at least nonce(12) + tag(16).
            if length < 28 {
                return Err(anyhow!(
                    "gcmtty: frame body too small: {} bytes (min 28)",
                    length
                ));
            }

            // Check we have the full frame body.
            let total = 8 + length;
            if buf.len() < total {
                eprintln!(
                    "stream_processor: gcmtty process_input BREAK buf.len={} < total={}",
                    buf.len(),
                    total
                );
                break; // wait for more data
            }

            // Consume exactly one frame from the front of the buffer.
            let header = buf[..8].to_vec();
            let frame_body = buf[8..total].to_vec();
            // Drain the consumed bytes from the buffer.
            self.input_buf.drain(..total);

            // Validate sequence number (strict monotonic).
            if seq <= self.input_counter {
                return Err(anyhow!(
                    "gcmtty: replay/reorder: expected seq > {}, got {}",
                    self.input_counter,
                    seq
                ));
            }

            let nonce_bytes = &frame_body[..12];
            let ciphertext_tag = &frame_body[12..];

            // Verify the counter embedded in the nonce matches the header seq.
            let nonce_seq = u32::from_be_bytes(nonce_bytes[8..12].try_into().unwrap());
            if nonce_seq != seq {
                return Err(anyhow!(
                    "gcmtty: header seq {} != nonce seq {}",
                    seq,
                    nonce_seq
                ));
            }

            let nonce = Nonce::from_slice(nonce_bytes);

            let plaintext = self
                .input_cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext_tag,
                        aad: &header,
                    },
                )
                .map_err(|e| anyhow!("gcmtty: decryption failed (seq={}): {:?}", seq, e))?;

            self.input_counter = seq;
            output.extend_from_slice(&plaintext);
        }

        Ok(output)
    }

    /// Encrypt `data` into a single authenticated frame sent to the remote peer.
    ///
    /// Frame layout emitted:
    ///   header(8B: length 4B + seq 4B) || nonce(12B) || ciphertext+tag
    fn process_output(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let seq = self.output_counter;
        self.output_counter = self
            .output_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("gcmtty: output counter overflow"))?;

        // Build nonce: 8 random bytes || seq (4B BE)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes[..8]);
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Compute expected payload length for the header: nonce(12) + plain.len() + tag(16)
        let payload_len = (12 + data.len() + 16) as u32;
        let header = Self::make_header(payload_len, seq);

        let ciphertext = self
            .output_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &header,
                },
            )
            .map_err(|e| anyhow!("gcmtty: encryption failed (seq={}): {:?}", seq, e))?;

        // Emit: header(8) || nonce(12) || ciphertext+tag
        let mut frame = Vec::with_capacity(8 + 12 + ciphertext.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }
}

impl fmt::Debug for AesGcmTtyProcessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmTtyProcessor")
            .field("input_cipher", &"<hidden>")
            .field("output_cipher", &"<hidden>")
            .finish()
    }
}
