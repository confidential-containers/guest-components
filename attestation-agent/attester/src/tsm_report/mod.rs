// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::EnumString;
use tempfile::tempdir_in;
use thiserror::Error;
use tracing::{error, trace};
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

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
    #[error("Failed to generate TSM Report: inblob write conflict (generation={0}, expected 1)")]
    InblobConflict(u32),
    #[error("Failed to generate TSM Report: missing inblob (len=0)")]
    InblobLen,
    #[error(
        "Failed to set TSM Report Privlevel: supplied privlevel {0} is not in range [privlevel_floor ({1}), TSM_PRIVLEVEL_MAX (3)]: ({2})"
    )]
    PrivlevelInvalid(u8, u8, #[source] std::io::Error),
    #[error("Failed to generate TSM Report: generation mismatch (generation={0}, expected {1})")]
    GenerationMismatch(u32, u32),
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
}

/// TsmReportPath instance represents a unique path on ConfigFS
/// provided by the TSM_REPORT attestation ABI. Currently, each
/// instance is a one-shot attestation request and the path is
/// automatically removed when the instance goes out of scope.
pub struct TsmReportPath {
    path: PathBuf,
    expected_generation: RefCell<u32>,
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

        let expected_generation = RefCell::new(Self::get_tsm_report_generation(&path)?);

        Ok(Self {
            path,
            expected_generation,
        })
    }

    pub fn attestation_report(
        &self,
        provider_data: TsmReportData,
    ) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let report_data = match provider_data {
            TsmReportData::Cca(inblob) => inblob,
            TsmReportData::Tdx(inblob) => inblob,
            TsmReportData::Sev(inblob) => inblob,
        };

        if report_data.is_empty() {
            return Err(TsmReportError::InblobLen);
        }

        self.write_inblob(&report_data)?;

        let q = std::fs::read(report_path.join("outblob")).map_err(|e| {
            tracing::error!(
                "Failed to read outblob from report path: {:?}, error: {:?}",
                report_path,
                e
            );
            TsmReportError::Access("outblob", e)
        })?;

        // Check that the expected generation matches the current generation maintained by the kernel before returning the report data.
        //  If it doesn't match we should assume another process has modified the report,
        //  invalidating our view of the report.
        self.check_tsm_report_generation()?;

        Ok(q)
    }

    pub fn supplemental_data(&self) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let aux = std::fs::read(report_path.join("auxblob")).map_err(|e| {
            tracing::error!(
                "Failed to read auxblob from report path: {:?}, error: {:?}",
                report_path,
                e
            );
            TsmReportError::Access("auxblob", e)
        })?;

        // Check that the expected generation matches the current generation in the kernel before returning the supplemental data.
        //  If it doesn't match, we should assume another process has modified the report,
        //  invalidating our view of the report.
        self.check_tsm_report_generation()?;

        Ok(aux)
    }

    /// get_tsm_report_generation returns the generation of a configfs-tsm report according to the kernel.
    ///
    /// Each write to any attribute of the report increments the generation of that report.
    pub fn get_tsm_report_generation(report_path: &Path) -> Result<u32, TsmReportError> {
        let g = std::fs::read_to_string(report_path.join("generation"))
            .map_err(|e| TsmReportError::Access("generation", e))?;

        let generation = g
            .trim_matches('\n')
            .to_string()
            .parse::<u32>()
            .map_err(TsmReportError::Parse);

        generation
    }

    /// check_tsm_report_generation checks if the expected generation of this TsmReportPath instance matches the generation of the Configfs-TSM report maintained by the kernel.
    /// Returns an error if the expected generation does not match the current generation in the kernel.
    ///
    /// This is meant to detect concurrent modifications to the Tsm Report by other processes, preventing
    /// the race condition that someone else could use the same temporary
    /// directory to generate a quote.
    pub fn check_tsm_report_generation(&self) -> Result<&Self, TsmReportError> {
        let expected = self.expected_generation.borrow().clone();
        let real = Self::get_tsm_report_generation(&self.path)?;
        if expected != real {
            error!(
                "Generation Mismatch for TSM Report at {:?}. \
                The report might have been modified by another process and therefore cannot be trusted. \
                (Expected: {}, Real: {})",
                &self.path, expected, real
            );
            return Err(TsmReportError::GenerationMismatch(real, expected));
        }
        Ok(self)
    }

    /// write_inblob writes the given report data to the inblob attribute of the Configfs-TSM report, updating the generation of report in the kernel.
    ///
    /// If successful, this operation also increments the expected generation of the TsmReportPath instance.
    fn write_inblob(&self, report_data: &[u8]) -> Result<&Self, TsmReportError> {
        self.check_tsm_report_generation()?;

        let report_path = self.path.as_path();
        std::fs::write(report_path.join("inblob"), report_data)
            .map_err(|e| TsmReportError::Access("inblob", e))?;
        trace!(
            "Successfully wrote Report Data to inblob for TSM report {:?}: {:?}",
            &self.path, report_data
        );
        self.increment_expected_generation();
        Ok(self)
    }

    /// increment_expected_generation increments the expected generation of the TsmReportPath instance.
    ///
    /// This should be called after successfully writing to any attribute of the Configfs-TSM report
    ///  and has been made public to allow functions outside of this module to increment the expected generation when necessary
    /// (e.g., increasing the expected generation of the report after setting the SNP VMPL).
    pub fn increment_expected_generation(&self) {
        let curr_gen = self.expected_generation.borrow().clone();
        let next_gen = curr_gen + 1;
        trace!(
            "Incrementing expected generation for TSM Report {:?}: {} => {}...",
            &self.path, curr_gen, next_gen
        );
        *self.expected_generation.borrow_mut() = next_gen;
    }

    /// report_path returns the file system path of the Configfs-TSM report associated with this TsmReportPath instance.
    ///
    /// Use this to hook into the TSM report through the file system.
    ///
    /// This has been made public to allow functions outside of this module to access the report path
    /// in case they need to directly retrieve or modify attributes of the report.
    /// (e.g., when setting the SNP VMPL of the report or when reading the report's @privlevel_floor attribute).
    pub fn report_path(&self) -> &Path {
        &self.path
    }
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
    #[case("generation", "1\n", false)]
    #[case("generation", "2\n", true)]
    #[case("generation", "parseerror\n", true)]
    fn test_tsm_report(#[case] file: &str, #[case] file_data: &str, #[case] expect_error: bool) {
        // Manually create TsmReportPath instance
        // to bypass using the real TSM_REPORT_PATH

        // Persist the tempDir on the disk past when the `p` variable goes out of scope
        let p = tempfile::tempdir().unwrap();
        let path = p.keep();

        // Pass the location of the persisted tempDir into the TsmReportPath instance,
        //  allowing TsmReportPath's Drop trait to remove the persisted tmpDir from disk when
        //  the instance goes out of scope.
        let tmp_report = TsmReportPath {
            path,
            expected_generation: RefCell::new(1),
        };

        // Write the test data to the appropriate file within the temporary report path.
        std::fs::write(tmp_report.path.as_path().join(file), file_data).unwrap();

        match file {
            "provider" => assert_eq!(
                expect_error,
                check_tsm_report_provider(tmp_report.path.as_path(), TsmReportProvider::Tdx)
                    .is_err()
            ),
            "generation" => assert_eq!(
                expect_error,
                tmp_report.check_tsm_report_generation().is_err(),
            ),
            _ => unimplemented!(),
        }
    }
}
