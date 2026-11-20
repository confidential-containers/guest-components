// Copyright (c) 2026 XHawk Corp
//
// SPDX-License-Identifier: Apache-2.0
//

//! AWS Nitro Enclaves attester.
//!
//! Requests an attestation document from the Nitro Secure Module (`/dev/nsm`).
//! The document is a COSE_Sign1 signed by a chain to the AWS Nitro Enclaves
//! root, and is appraised by Trustee's `nitro_enclave` verifier.
//!
//! - `report_data` is sent as the document's `nonce`, unchanged.
//! - Nitro has no host-set register for InitData. `bind_init_data` keeps the
//!   digest for the life of the process and every later document carries it
//!   as `user_data`. The binding therefore rests on the enclave's measured
//!   image (PCR0), which contains the code that calls it. The first bind wins,
//!   so the image must bind at startup, before any other client can reach
//!   the attestation agent: start it with `--initdata-toml`, which binds
//!   before the agent serves requests.
//! - `public_key` is not used: the KBS TEE key travels in the runtime data,
//!   which `report_data` already binds.

use std::sync::OnceLock;

use super::{Attester, InitDataResult, TeeEvidence};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde_json::json;

const NSM_DEVICE: &str = "/dev/nsm";

/// The NSM accepts at most 512 bytes of `nonce` and of `user_data`.
const NSM_FIELD_MAX: usize = 512;

/// Version of the evidence layout, as Trustee's verifier expects it.
const EVIDENCE_VERSION: u32 = 1;

/// The Nitro Secure Module, behind a seam so tests need no `/dev/nsm`.
pub(crate) trait Nsm: Send + Sync {
    /// Request an attestation document with the given `nonce` and `user_data`.
    fn attestation(&self, nonce: Vec<u8>, user_data: Option<Vec<u8>>) -> Result<Vec<u8>>;
}

/// The NSM device of the enclave this process runs in.
struct DevNsm;

impl Nsm for DevNsm {
    fn attestation(&self, nonce: Vec<u8>, user_data: Option<Vec<u8>>) -> Result<Vec<u8>> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
        use serde_bytes::ByteBuf;

        let fd = nsm_init();
        if fd < 0 {
            // `nsm_init` only logs why; open the device again for the cause.
            let cause = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(NSM_DEVICE)
                .err()
                .map_or_else(|| "unknown error".to_string(), |e| e.to_string());
            bail!("failed to open {NSM_DEVICE}: {cause}");
        }
        let response = nsm_process_request(
            fd,
            Request::Attestation {
                nonce: Some(ByteBuf::from(nonce)),
                user_data: user_data.map(ByteBuf::from),
                public_key: None,
            },
        );
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => bail!("NSM refused the attestation request: {code:?}"),
            _ => bail!("NSM returned an unexpected response to an attestation request"),
        }
    }
}

pub fn detect_platform() -> bool {
    std::path::Path::new(NSM_DEVICE).exists()
}

/// The InitData digest bound in this process.
///
/// Process-wide rather than per instance: the attestation agent binds on its
/// primary attester at startup, but some evidence paths (the KBS token getter,
/// `NativeEvidenceProvider::new`) build a fresh attester, and those must send
/// the same `user_data`. Set at most once; it cannot change afterwards.
static INIT_DATA_DIGEST: OnceLock<Vec<u8>> = OnceLock::new();

pub struct NitroEnclaveAttester {
    nsm: Box<dyn Nsm>,
    pub(crate) binding: &'static OnceLock<Vec<u8>>,
}

impl Default for NitroEnclaveAttester {
    fn default() -> Self {
        Self::with_nsm(Box::new(DevNsm), &INIT_DATA_DIGEST)
    }
}

impl NitroEnclaveAttester {
    pub(crate) fn with_nsm(nsm: Box<dyn Nsm>, binding: &'static OnceLock<Vec<u8>>) -> Self {
        Self { nsm, binding }
    }
}

#[async_trait::async_trait]
impl Attester for NitroEnclaveAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        ensure!(
            report_data.len() <= NSM_FIELD_MAX,
            "report data is {} bytes; the NSM nonce holds at most {NSM_FIELD_MAX}",
            report_data.len()
        );
        let user_data = self.binding.get().cloned();

        let document = self
            .nsm
            .attestation(report_data, user_data)
            .context("failed to get a Nitro Enclave attestation document")?;

        Ok(json!({
            "version": EVIDENCE_VERSION,
            "attestation_document": base64::engine::general_purpose::STANDARD.encode(document),
        }))
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        ensure!(!init_data_digest.is_empty(), "the InitData digest is empty");
        ensure!(
            init_data_digest.len() <= NSM_FIELD_MAX,
            "the InitData digest is {} bytes; the NSM user_data holds at most {NSM_FIELD_MAX}",
            init_data_digest.len()
        );

        // Atomic: of concurrent first binds, exactly one value wins.
        let bound = self.binding.get_or_init(|| init_data_digest.to_vec());
        ensure!(
            bound.as_slice() == init_data_digest,
            "an InitData digest is already bound ({}); refusing to bind {}",
            hex::encode(bound),
            hex::encode(init_data_digest)
        );
        Ok(InitDataResult::Ok)
    }
}

#[cfg(test)]
mod tests;
