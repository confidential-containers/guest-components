// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use attester::{detect_attestable_devices, detect_tee_type, BoxedAttester, TeeEvidence};
use kbs_types::Tee;

use super::EvidenceProvider;

use crate::{Error, Result};

pub struct NativeEvidenceProvider {
    primary_tee: Tee,
    primary_attester: BoxedAttester,
    additional_attesters: Vec<(Tee, BoxedAttester)>,
}

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        let primary_tee = detect_tee_type();
        let primary_attester = BoxedAttester::try_from(primary_tee).map_err(|e| {
            Error::NativeEvidenceProvider(format!("failed to initialize primary attester: {e}"))
        })?;
        let additional_attesters = detect_attestable_devices()
            .into_iter()
            .map(|tee| -> Result<_> {
                let boxed_attester = TryInto::<BoxedAttester>::try_into(tee).map_err(|e| {
                    Error::NativeEvidenceProvider(format!(
                        "failed to initialize additional attester: {e}"
                    ))
                })?;
                Ok((tee, boxed_attester))
            })
            .collect::<Result<Vec<(Tee, BoxedAttester)>>>()?;
        Ok(Self {
            primary_tee,
            primary_attester,
            additional_attesters,
        })
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence> {
        self.primary_attester
            .get_evidence(runtime_data)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))
    }

    async fn get_additional_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        let mut additional_evidences_map = HashMap::new();

        for (tee, attester) in &self.additional_attesters {
            let evidence = attester
                .get_evidence(runtime_data.to_vec())
                .await
                .map_err(|e| Error::GetEvidence(e.to_string()))?;
            additional_evidences_map.insert(tee, evidence);
        }

        if additional_evidences_map.is_empty() {
            return Ok("".into());
        }

        let additional_evidences = serde_json::to_string(&additional_evidences_map)
            .map_err(|e| Error::GetEvidence(e.to_string()))?;

        Ok(additional_evidences)
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(self.primary_tee)
    }
}
