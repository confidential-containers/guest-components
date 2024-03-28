// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use crate::se::seattest::FakeSeAttest;
use crate::se::seattest::SeImplAttester;
use anyhow::*;
use base64::prelude::*;
use serde::{Deserialize, Serialize};

pub mod seattest;

pub fn detect_platform() -> bool {
    // TODO replace FakeSeAttest with real crate
    let attester = FakeSeAttest::default();
    attester.is_se_guest()
}

#[derive(Serialize, Deserialize)]
struct SeEvidence {
    quote: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SeAttester {}

#[async_trait::async_trait]
impl Attester for SeAttester {
    async fn get_evidence(&self, attestation_request: Vec<u8>) -> Result<String> {
        // TODO replace FakeSeAttest with real crate
        let attester = FakeSeAttest::default();
        let userdata = "userdata".as_bytes().to_vec();
        let evidence = attester.perform(attestation_request, userdata).await?;

        Ok(BASE64_STANDARD.encode(evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_se_get_evidence() {
        let attester = SeAttester::default();
        let report_data: Vec<u8> = vec![0; 64];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
