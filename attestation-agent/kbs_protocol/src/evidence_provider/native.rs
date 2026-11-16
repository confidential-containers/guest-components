// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use attester::{BoxedAttester, TeeEvidence, detect_attestable_devices, detect_tee_type};
use kbs_types::Tee;

use super::EvidenceProvider;

use crate::{Error, Result};

pub struct NativeEvidenceProvider {
    primary_tee: Tee,
    primary_attester: BoxedAttester,
    additional_attesters: Vec<(Tee, BoxedAttester)>,
}

impl NativeEvidenceProvider {
    /// Detect the primary TEE and the attestable devices, then build their attesters.
    pub fn new() -> Result<Self> {
        Self::new_with_tees(detect_tee_type(), detect_attestable_devices())
    }

    /// Build the attesters for TEEs that were already detected, instead of detecting here.
    pub fn new_with_tees(primary_tee: Tee, additional_tees: Vec<Tee>) -> Result<Self> {
        let primary_attester = BoxedAttester::try_from(primary_tee).map_err(|e| {
            Error::NativeEvidenceProvider(format!("failed to initialize primary attester: {e}"))
        })?;
        let additional_attesters = additional_tees
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::with_additional_tee(Tee::Sample, vec![Tee::SampleDevice], Some(Tee::SampleDevice))]
    #[case::without_additional_tees(Tee::Sample, vec![], None)]
    #[case::explicit_primary_tee(Tee::SampleDevice, vec![], None)]
    #[tokio::test]
    async fn new_with_tees_builds_the_given_attesters(
        #[case] primary_tee: Tee,
        #[case] additional_tees: Vec<Tee>,
        #[case] expected_additional: Option<Tee>,
    ) {
        let provider = NativeEvidenceProvider::new_with_tees(primary_tee, additional_tees)
            .expect("build provider");
        assert_eq!(
            provider.get_tee_type().await.expect("tee type"),
            primary_tee
        );
        provider
            .primary_evidence(vec![1, 2, 3])
            .await
            .expect("primary evidence");
        let additional = provider
            .get_additional_evidence(vec![])
            .await
            .expect("additional evidence");
        match expected_additional {
            None => assert_eq!(additional, ""),
            Some(tee) => {
                let additional: HashMap<Tee, TeeEvidence> =
                    serde_json::from_str(&additional).expect("json");
                assert_eq!(additional.len(), 1);
                assert!(additional.contains_key(&tee));
            }
        }
    }
}
