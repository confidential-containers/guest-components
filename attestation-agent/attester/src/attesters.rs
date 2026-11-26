// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::BoxedAttester;
use kbs_types::Tee;
use std::sync::OnceLock;

/// A collection of compiled attesters; construction does not initialize TPM hardware.
pub struct Attesters {
    primary_attesters: PrimaryAttesters,
    additional_attesters: AdditionalAttesters,
}

impl Attesters {
    /// Returns the process-wide registry, constructing its attesters only once.
    pub fn get() -> &'static Self {
        static ATTESTERS: OnceLock<Attesters> = OnceLock::new();
        ATTESTERS.get_or_init(|| Self {
            primary_attesters: PrimaryAttesters::new(),
            additional_attesters: AdditionalAttesters::new(),
        })
    }

    /// Returns the names of all compiled attesters, without detecting hardware.
    pub fn get_attester_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for attester in self
            .primary_attesters
            .entries
            .iter()
            .chain(&self.additional_attesters.entries)
        {
            let name = attester.to_string();
            if name != "tpm-attester" || !names.contains(&name) {
                names.push(name);
            }
        }
        names
    }

    /// Returns the first detected primary TEE, falling back to Sample.
    pub fn get_primary_tee(&self) -> Tee {
        self.primary_attesters.get_tee()
    }

    /// Collects detected additional TEEs. NVIDIA DPU evidence is explicit-only.
    /// The primary TEE is selected before probing additional attesters.
    pub fn get_additional_tees(&self) -> Vec<Tee> {
        let primary_tee = self.get_primary_tee();
        let mut tees = self.additional_attesters.get_tees();

        if !tees.contains(&Tee::Tpm) {
            return tees;
        }

        if primary_tee == Tee::Tpm {
            tees.retain(|tee| *tee != Tee::Tpm);
        } else {
            tracing::warn!(
                "The TPM device was detected as an additional device, but please note that it is not bound to the TEE, so there may be security risks."
            );
        }
        tees
    }
}

struct PrimaryAttesters {
    entries: Vec<BoxedAttester>,
}

impl PrimaryAttesters {
    fn new() -> Self {
        Self {
            // Preserve primary detection priority, with Sample as the fallback.
            entries: vec![
                #[cfg(feature = "tdx-attester")]
                Box::<crate::tdx::TdxAttester>::default(),
                #[cfg(feature = "sgx-attester")]
                Box::<crate::sgx_dcap::SgxDcapAttester>::default(),
                #[cfg(feature = "az-tdx-vtpm-attester")]
                Box::new(crate::az_tdx_vtpm::AzTdxVtpmAttester),
                #[cfg(feature = "az-snp-vtpm-attester")]
                Box::new(crate::az_snp_vtpm::AzSnpVtpmAttester),
                #[cfg(feature = "snp-attester")]
                Box::<crate::snp::SnpAttester>::default(),
                #[cfg(feature = "csv-attester")]
                Box::<crate::csv::CsvAttester>::default(),
                #[cfg(feature = "cca-attester")]
                Box::<crate::cca::CcaAttester>::default(),
                #[cfg(feature = "se-attester")]
                Box::<crate::se::SeAttester>::default(),
                #[cfg(feature = "tpm-attester")]
                Box::<crate::tpm::TpmAttester>::default(),
                Box::<crate::sample::SampleAttester>::default(),
            ],
        }
    }

    fn get_tee(&self) -> Tee {
        let tee = self
            .entries
            .iter()
            .find_map(|attester| attester.detect_tee())
            .unwrap_or(Tee::Sample);

        if tee == Tee::Tpm {
            tracing::warn!(
                "The TPM device was detected, but please note that it is not bound to the TEE, so there may be security risks."
            );
        }

        if tee == Tee::Sample {
            tracing::warn!(
                "No TEE platform detected. Sample Attester will be used.
         If you are expecting to collect evidence from inside a confidential guest,
         either your guest is not configured correctly, or your attestation client
         was not built with support for the platform.

         Verify that your guest is a confidential guest and that your client
         (such as kbs-client or attestation-agent) was built with the feature
         corresponding to your platform.

         Attestation will continue using the fallback sample attester."
            );
        }
        tee
    }
}

struct AdditionalAttesters {
    entries: Vec<BoxedAttester>,
}

impl AdditionalAttesters {
    fn new() -> Self {
        Self {
            entries: vec![
                #[cfg(feature = "nvidia-attester")]
                Box::<crate::nvidia::NvAttester>::default(),
                Box::<crate::sample_device::SampleDeviceAttester>::default(),
                #[cfg(feature = "hygon-dcu-attester")]
                Box::<crate::hygon_dcu::DcuAttester>::default(),
                // Additional TPM evidence is not applicable in Azure or with TDX.
                #[cfg(all(
                    feature = "tpm-attester",
                    not(feature = "tdx-attester"),
                    not(feature = "az-snp-vtpm-attester"),
                    not(feature = "az-tdx-vtpm-attester")
                ))]
                Box::<crate::tpm::TpmAttester>::default(),
                // DPU evidence remains explicit-only; retain the object for names.
                #[cfg(feature = "nvidia-dpu-attester")]
                Box::<crate::nvidia_dpu::NvidiaDpuAttester>::default(),
            ],
        }
    }

    fn get_tees(&self) -> Vec<Tee> {
        self.entries
            .iter()
            .filter_map(|attester| attester.detect_tee())
            .filter(|tee| *tee != Tee::NvidiaDpu)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAttester {
        tee: Tee,
        detect: fn() -> bool,
    }

    impl std::fmt::Display for TestAttester {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.tee {
                Tee::Tpm => f.write_str("tpm-attester"),
                _ => write!(f, "{:?}-attester", self.tee),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::Attester for TestAttester {
        fn detect_tee(&self) -> Option<Tee> {
            (self.detect)().then_some(self.tee)
        }

        async fn get_evidence(&self, _: Vec<u8>) -> anyhow::Result<crate::TeeEvidence> {
            anyhow::bail!("Test attester does not provide evidence")
        }
    }

    fn entry(tee: Tee, detect: fn() -> bool) -> BoxedAttester {
        Box::new(TestAttester { tee, detect })
    }

    fn attesters(
        primary_entries: Vec<BoxedAttester>,
        additional_entries: Vec<BoxedAttester>,
    ) -> Attesters {
        Attesters {
            primary_attesters: PrimaryAttesters {
                entries: primary_entries,
            },
            additional_attesters: AdditionalAttesters {
                entries: additional_entries,
            },
        }
    }

    #[test]
    fn registry_is_shared_across_threads() {
        let attesters = Attesters::get();
        assert!(std::ptr::eq(attesters, Attesters::get()));
        let other = std::thread::spawn(Attesters::get).join().unwrap();
        assert!(std::ptr::eq(attesters, other));
    }

    #[test]
    fn attester_objects_display_their_names() {
        let attesters = Attesters::get();
        let names = attesters.get_attester_names();
        let expected = vec![
            #[cfg(feature = "tdx-attester")]
            "tdx-attester",
            #[cfg(feature = "sgx-attester")]
            "sgx-attester",
            #[cfg(feature = "az-tdx-vtpm-attester")]
            "az-tdx-vtpm-attester",
            #[cfg(feature = "az-snp-vtpm-attester")]
            "az-snp-vtpm-attester",
            #[cfg(feature = "snp-attester")]
            "snp-attester",
            #[cfg(feature = "csv-attester")]
            "csv-attester",
            #[cfg(feature = "cca-attester")]
            "cca-attester",
            #[cfg(feature = "se-attester")]
            "se-attester",
            #[cfg(feature = "tpm-attester")]
            "tpm-attester",
            "sample-attester",
            #[cfg(feature = "nvidia-attester")]
            "nvidia-attester",
            "sample-device-attester",
            #[cfg(feature = "hygon-dcu-attester")]
            "hygon-dcu-attester",
            #[cfg(feature = "nvidia-dpu-attester")]
            "nvidia-dpu-attester",
        ];
        assert_eq!(names, expected);
    }

    #[test]
    fn get_attester_names_does_not_detect_hardware() {
        let attesters = attesters(
            vec![
                entry(Tee::Tdx, || panic!("Hardware must not be probed")),
                entry(Tee::Tpm, || panic!("Hardware must not be probed")),
            ],
            vec![
                entry(Tee::Tpm, || panic!("Hardware must not be probed")),
                entry(Tee::NvidiaDpu, || panic!("Hardware must not be probed")),
            ],
        );
        assert_eq!(
            attesters.get_attester_names(),
            vec!["Tdx-attester", "tpm-attester", "NvidiaDpu-attester"]
        );
        assert!(empty_attesters().get_attester_names().is_empty());
    }

    #[test]
    fn sample_detection_returns_its_tee_type() {
        use crate::Attester;
        assert_eq!(
            crate::sample::SampleAttester::default().detect_tee(),
            Some(Tee::Sample)
        );
    }

    fn empty_attesters() -> Attesters {
        attesters(vec![], vec![])
    }

    #[test]
    fn primary_detection_stops_at_first_match_without_probing_additional() {
        let expected = vec![
            Tee::Tdx,
            Tee::Sgx,
            Tee::AzTdxVtpm,
            Tee::AzSnpVtpm,
            Tee::Snp,
            Tee::Csv,
            Tee::Cca,
            Tee::Se,
            Tee::Tpm,
            Tee::Sample,
        ];
        for (index, tee) in expected.iter().enumerate() {
            let mut primary_entries: Vec<_> = expected[..index]
                .iter()
                .map(|tee| entry(*tee, || false))
                .collect();
            primary_entries.push(entry(*tee, || true));
            primary_entries.extend(
                expected[index + 1..]
                    .iter()
                    .map(|tee| entry(*tee, || panic!("Later primary must not be probed"))),
            );
            let attesters = attesters(
                primary_entries,
                vec![entry(Tee::Nvidia, || panic!("Additional probe"))],
            );
            assert_eq!(attesters.get_primary_tee(), *tee);
        }
    }

    #[test]
    fn primary_detection_skips_none_and_selects_sample_fallback() {
        let mut attesters = attesters(
            vec![
                entry(Tee::Tdx, || false),
                entry(Tee::Cca, || true),
                entry(Tee::Sample, || true),
            ],
            vec![],
        );
        assert_eq!(attesters.get_primary_tee(), Tee::Cca);
        attesters.primary_attesters.entries.remove(1);
        assert_eq!(attesters.get_primary_tee(), Tee::Sample);
        for attesters in [attesters, empty_attesters()] {
            assert_eq!(attesters.get_primary_tee(), Tee::Sample);
        }
    }

    #[test]
    fn additional_detection_skips_none_and_excludes_dpu() {
        let attesters = attesters(
            vec![entry(Tee::Tdx, || true)],
            vec![
                entry(Tee::Nvidia, || true),
                entry(Tee::SampleDevice, || true),
                entry(Tee::HygonDcu, || true),
                entry(Tee::Tpm, || false),
                entry(Tee::NvidiaDpu, || true),
            ],
        );
        assert_eq!(
            attesters.get_additional_tees(),
            vec![Tee::Nvidia, Tee::SampleDevice, Tee::HygonDcu]
        );
        assert!(empty_attesters().get_additional_tees().is_empty());
    }

    #[test]
    fn primary_is_detected_before_additional_tpm() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static PRIMARY_DETECTED: AtomicBool = AtomicBool::new(false);
        PRIMARY_DETECTED.store(false, Ordering::SeqCst);
        let attesters = attesters(
            vec![entry(Tee::Cca, || {
                PRIMARY_DETECTED.store(true, Ordering::SeqCst);
                true
            })],
            vec![entry(Tee::Tpm, || {
                assert!(PRIMARY_DETECTED.load(Ordering::SeqCst));
                true
            })],
        );
        assert_eq!(attesters.get_additional_tees(), vec![Tee::Tpm]);
    }

    #[test]
    fn additional_tpm_is_removed_only_when_tpm_is_primary() {
        for primary in [Tee::Tpm, Tee::Cca, Tee::Tdx] {
            let attesters = attesters(
                vec![entry(primary, || true), entry(Tee::Tpm, || true)],
                vec![
                    entry(Tee::Nvidia, || true),
                    entry(Tee::SampleDevice, || false),
                    entry(Tee::HygonDcu, || true),
                    entry(Tee::Tpm, || true),
                    entry(Tee::NvidiaDpu, || true),
                ],
            );
            let mut expected = vec![Tee::Nvidia, Tee::HygonDcu];
            if primary != Tee::Tpm {
                expected.push(Tee::Tpm);
            }
            assert_eq!(attesters.get_additional_tees(), expected);
        }
    }
}
