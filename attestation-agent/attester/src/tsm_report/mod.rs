// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::EnumString;
use tempfile::tempdir_in;
use thiserror::Error;
// A standard one-shot request writes only inblob.
const STANDARD_REPORT_EXPECTED_GENERATION: u32 = 1;
// SVSM vTPM additionally writes service_provider and service_guid.
const SVSM_VTPM_EXPECTED_GENERATION: u32 = 3;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";
const SVSM_SERVICE_PROVIDER: &str = "svsm";
pub const SVSM_VTPM_SERVICE_GUID: &str = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";
const SVSM_REPORT_DATA_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum TsmReportError {
    #[error("Failed to access TSM Report path")]
    NoTsmReports,
    #[error("Failed to create TSM Report path instance: {0}")]
    Open(#[from] std::io::Error),
    #[error("Failed to access TSM Report attribute: {0} ({1})")]
    Access(&'static str, #[source] std::io::Error),
    #[error("Failed to parse TSM Report attribute 'generation': {0}")]
    Parse(#[source] std::num::ParseIntError),
    #[error("Failed to open TSM Report path: missing provider {0:?} (provider={1:?})")]
    MissingProvider(TsmReportProvider, TsmReportProvider),
    #[error("Failed to open TSM Report path: unknown provider ({0})")]
    UnknownProvider(#[from] strum::ParseError),
    #[error("Failed to generate TSM Report: missing inblob (len=0)")]
    InblobLen,
    #[error("Failed to generate SVSM TSM Report: invalid inblob length (len={0}, expected 64)")]
    SvsmInblobLen(usize),
    #[error(
        "Failed to generate TSM Report: write conflict (generation={generation}, expected {expected})"
    )]
    WriteConflict { generation: u32, expected: u32 },
}

#[derive(PartialEq, Debug, EnumString)]
pub enum TsmReportProvider {
    #[strum(serialize = "arm_cca_guest\n")]
    Cca,
    #[strum(serialize = "tdx_guest\n")]
    Tdx,
    #[strum(serialize = "sev_guest\n")]
    Sev,
}

pub enum TsmReportData {
    Cca(Vec<u8>),
    Tdx(Vec<u8>),
    Sev(Vec<u8>),
    SvsmVtpm(Vec<u8>),
}

/// TsmReportPath instance represents a unique path on ConfigFS
/// provided by the TSM_REPORT attestation ABI. Currently, each
/// instance is a one-shot attestation request and the path is
/// automatically removed when the instance goes out of scope.
pub struct TsmReportPath {
    path: PathBuf,
}

impl Drop for TsmReportPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.path.as_path())
            .map_err(|e| tracing::error!("Failed to remove TSM Report directory: {e}"));
    }
}

impl TsmReportPath {
    pub fn new(wanted: TsmReportProvider) -> Result<Self, TsmReportError> {
        if !Path::new(TSM_REPORT_PATH).exists() {
            return Err(TsmReportError::NoTsmReports);
        }

        let p = tempdir_in(TSM_REPORT_PATH).map_err(TsmReportError::Open)?;

        // Remove the Drop set by tempdir_in() since it errors on ConfigFS
        // and leaks the created path. We implement our own Drop that removes the
        // path (rmdir way) when TsmReportPath instance goes out of scope.
        let path = p.keep();

        check_tsm_report_provider(path.as_path(), wanted).inspect_err(|_| {
            let _ = std::fs::remove_dir(path.as_path());
        })?;

        Ok(Self { path })
    }

    pub fn attestation_report(
        &self,
        provider_data: TsmReportData,
    ) -> Result<Vec<u8>, TsmReportError> {
        attestation_report_from_path(self.path.as_path(), provider_data)
    }

    pub fn supplemental_data(&self) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let aux = std::fs::read(report_path.join("auxblob"))
            .map_err(|e| TsmReportError::Access("auxblob", e))?;

        check_write_race(report_path, STANDARD_REPORT_EXPECTED_GENERATION)?;

        Ok(aux)
    }
}

fn attestation_report_from_path(
    report_path: &Path,
    provider_data: TsmReportData,
) -> Result<Vec<u8>, TsmReportError> {
    let (report_data, expected_generation) = match provider_data {
        TsmReportData::Cca(data) | TsmReportData::Tdx(data) | TsmReportData::Sev(data) => {
            (data, STANDARD_REPORT_EXPECTED_GENERATION)
        }

        TsmReportData::SvsmVtpm(nonce) => {
            if nonce.len() != SVSM_REPORT_DATA_SIZE {
                return Err(TsmReportError::SvsmInblobLen(nonce.len()));
            }

            // A non-null GUID requests only the vTPM service. Omitting the
            // manifest version selects the default (version 0).
            std::fs::write(report_path.join("service_provider"), SVSM_SERVICE_PROVIDER)
                .map_err(|e| TsmReportError::Access("service_provider", e))?;
            std::fs::write(report_path.join("service_guid"), SVSM_VTPM_SERVICE_GUID)
                .map_err(|e| TsmReportError::Access("service_guid", e))?;
            (nonce, SVSM_VTPM_EXPECTED_GENERATION)
        }
    };

    if report_data.is_empty() {
        return Err(TsmReportError::InblobLen);
    }

    std::fs::write(report_path.join("inblob"), report_data)
        .map_err(|e| TsmReportError::Access("inblob", e))?;
    let report = std::fs::read(report_path.join("outblob"))
        .map_err(|e| TsmReportError::Access("outblob", e))?;

    check_write_race(report_path, expected_generation)?;

    Ok(report)
}

/// check_write_race checks that the returned outblob/auxblob
/// matches the quote generation request originally triggered when
/// inblob was written by the TsmReportPath instance. It checks that
/// generation matches expected_generation, accounting for writes to
/// both inblob and any service configuration attributes. It prevents
/// the race condition that someone else could use the same temporary
/// directory to generate a quote.
fn check_write_race(report_path: &Path, expected_generation: u32) -> Result<(), TsmReportError> {
    let generation = std::fs::read_to_string(report_path.join("generation"))
        .map_err(|e| TsmReportError::Access("generation", e))?;

    let generation = generation
        .trim_matches('\n')
        .parse::<u32>()
        .map_err(TsmReportError::Parse)?;

    if generation != expected_generation {
        return Err(TsmReportError::WriteConflict {
            generation,
            expected: expected_generation,
        });
    }

    Ok(())
}

/// check_tsm_report_provider checks that the TEE is
/// the requested TsmReportProvider.
fn check_tsm_report_provider(
    report_path: &Path,
    wanted: TsmReportProvider,
) -> Result<(), TsmReportError> {
    let report_provider = std::fs::read_to_string(report_path.join("provider"))
        .map_err(|e| TsmReportError::Access("provider", e))?;

    match TsmReportProvider::from_str(&report_provider) {
        Ok(provider) => {
            if provider == wanted {
                Ok(())
            } else {
                Err(TsmReportError::MissingProvider(wanted, provider))
            }
        }
        Err(e) => Err(TsmReportError::UnknownProvider(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("provider", "tdx_guest\n", false)]
    #[case("provider", "sev_guest\n", true)]
    #[case("provider", "foo_guest\n", true)]
    #[case("generation", "0\n", true)]
    #[case("generation", "1\n", false)]
    #[case("generation", "2\n", true)]
    #[case("generation", "parseerror\n", true)]
    fn test_tsm_report(#[case] file: &str, #[case] file_data: &str, #[case] expect_error: bool) {
        let tsm_dir = tempfile::tempdir().unwrap();

        std::fs::write(tsm_dir.path().join(file), file_data).unwrap();

        match file {
            "provider" => assert_eq!(
                expect_error,
                check_tsm_report_provider(tsm_dir.path(), TsmReportProvider::Tdx).is_err()
            ),
            "generation" => assert_eq!(
                expect_error,
                check_write_race(tsm_dir.path(), STANDARD_REPORT_EXPECTED_GENERATION).is_err(),
            ),
            _ => unimplemented!(),
        }
    }

    #[rstest]
    #[case(2, true)]
    #[case(3, false)]
    #[case(4, true)]
    fn test_expected_generation(#[case] generation: u32, #[case] expect_error: bool) {
        let tsm_dir = tempfile::tempdir().unwrap();
        std::fs::write(tsm_dir.path().join("generation"), generation.to_string()).unwrap();

        let result = check_write_race(tsm_dir.path(), 3);
        if expect_error {
            assert!(matches!(
                result,
                Err(TsmReportError::WriteConflict { generation: actual, expected: 3 })
                    if actual == generation
            ));
        } else {
            result.unwrap();
        }
    }

    /// Requires a real SVSM vTPM guest and permission to create ConfigFS requests.
    #[test]
    #[ignore = "requires SVSM vTPM hardware and root privileges"]
    fn test_svsm_vtpm_report_data_binding() {
        use sha2::{Digest, Sha512};

        let tsm = TsmReportPath::new(TsmReportProvider::Sev).unwrap();
        let nonce = vec![0x5a; SVSM_REPORT_DATA_SIZE];
        let report = tsm
            .attestation_report(TsmReportData::SvsmVtpm(nonce.clone()))
            .unwrap();
        let manifest = std::fs::read(tsm.path.join("manifestblob")).unwrap();
        assert!(!manifest.is_empty(), "SVSM must return the vTPM manifest");

        let mut hasher = Sha512::new();
        hasher.update(&nonce);
        hasher.update(&manifest);
        let expected = hasher.finalize();

        // SNP report REPORT_DATA occupies bytes 0x50..0x90.
        let report_data = report.get(0x50..0x90).expect("truncated SNP report");
        assert_eq!(report_data, &expected[..]);
        check_write_race(&tsm.path, SVSM_VTPM_EXPECTED_GENERATION).unwrap();
    }
}
