// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use kbs_types::Tee;
use std::collections::HashMap;

use attester::{detect_tee_types, BoxedAttester};

use super::EvidenceProvider;
use crate::{Error, Result};

/// The NativeEvidenceProvider is an interface between the RCAR client
/// of the kbs_protocol and the TEE attesters.
pub struct NativeEvidenceProvider {
    attesters: Vec<(Tee, BoxedAttester)>,
}

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        let tees = detect_tee_types();

        let mut attesters: Vec<(Tee, BoxedAttester)> = vec![];
        for tee in tees {
            attesters.push((
                tee,
                BoxedAttester::try_from(tee).map_err(|e| {
                    Error::NativeEvidenceProvider(format!("Failed to create TEE attester: {e:?}"))
                })?,
            ));
        }
        Ok(Self { attesters })
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        let mut evidence: HashMap<Tee, (String, String)> = HashMap::new();
        for (tee, attester) in &self.attesters {
            let ev = attester
                .get_evidence(runtime_data.clone())
                .await
                .map_err(|e| Error::GetEvidence(e.to_string()))?;

            evidence.insert(*tee, (attester.device_class(), ev));
        }

        Ok(serde_json::to_string(&evidence)
            .map_err(|e| Error::GetEvidence(format!("Failed to serialize evidence {e}")))?)
    }

    async fn get_tee_types(&self) -> Result<Vec<Tee>> {
        Ok(detect_tee_types())
    }
}
