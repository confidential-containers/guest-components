// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use serde::{Deserialize, Serialize};
use std::path::Path;

const CCA_DEVICE_PATH: &str = "/dev/cca_attestation";

// NOTE: The path might be different when the CCA feature is public available, will come back to update the actual path if needed.
pub fn detect_platform() -> bool {
    Path::new(CCA_DEVICE_PATH).exists()
}

#[derive(Debug, Default)]
pub struct CCAAttester {}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token
    token: Vec<u8>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct cca_ioctl_request {
    challenge: [u8; 64],
    token: [u8; 4096],
    token_length: u64,
}

nix::ioctl_readwrite!(cca_attestation_request, b'A', 1, cca_ioctl_request);

#[async_trait::async_trait]
impl Attester for CCAAttester {
    async fn get_evidence(&self, mut challenge: Vec<u8>) -> Result<String> {
        challenge.resize(64, 0);
        let token = attestation(challenge)?;
        let evidence = CcaEvidence { token };
        let ev = serde_json::to_string(&evidence).context("Serialize CCA evidence failed")?;
        Ok(ev)
    }
}

fn attestation(challenge: Vec<u8>) -> Result<Vec<u8>, Error> {
    log::info!("cca_test::attestation started");

    let challenge = challenge.as_slice().try_into()?;

    match open(CCA_DEVICE_PATH, OFlag::empty(), Mode::empty()) {
        Result::Ok(f) => {
            log::info!("cca_test::attestation opening attestation succeeded");
            let mut request = cca_ioctl_request {
                challenge,
                token: [0u8; 4096],
                token_length: 0u64,
            };

            // this is unsafe code block since ioctl call `cca_attestation_request` has the unsafe signature.
            match unsafe { cca_attestation_request(f, &mut request) } {
                Result::Ok(c) => {
                    log::info!("cca_test::attestation ioctl call succeeded ({})", c);
                    log::info!(
                        "cca_test::attestation token is {} bytes long",
                        request.token_length
                    );
                    let base64 = base64::engine::general_purpose::STANDARD
                        .encode(&request.token[0..(request.token_length as usize)]);
                    log::info!("cca_test::attestation token = {:x?}", base64);
                    let token = request.token[0..(request.token_length as usize)].to_vec();
                    close(f)?;
                    Ok(token)
                }
                Err(e) => {
                    log::error!("cca_test::attestation ioctl failed! {}", e);
                    close(f)?;
                    bail!(e)
                }
            }
        }
        Err(err) => {
            log::error!("cca_test::attestation opening attestation failed! {}", err);
            bail!(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_cca_get_evidence() {
        let attester = CCAAttester::default();
        let report_data: Vec<u8> = vec![0; 48];
        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
