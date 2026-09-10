// Copyright (c) 2026 Advanced Micro Devices
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::tsm_report::{TsmReportError, TsmReportPath};
use std::path::Path;
use tracing::{debug, error, trace, warn};

/// VMPrivilegeLevel represents a distinct Virtual Machine Privilege Level on an SNP-enabled confidential virtual machine (CVM)
///
/// Virtual Machine Privilege Levels (VMPLs) are hardware-enforced isolation rings (ranging from VMPL0 to VMPL3) inside an AMD Secure Encrypted Virtualization-Secure Nested Paging (AMD SEV) confidential virtual machine.
///
/// The default VMPrivilegeLevel for both this structure and for generating a TSM report on an SNP-enabled CVM is 0 (i.e. the highest privilege level).
#[derive(Default, Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(u8)] // Tells Rust to store this enum as an unsigned 8-bit integer
pub enum VMPrivilegeLevel {
    #[default]
    Zero = 0,
    One = 1,
    Two = 2,
    Three = 3,
}

impl VMPrivilegeLevel {
    /// MOST_PRIVILEGED returns the lowest VMPL ring (the highest privilege level)
    pub const MOST_PRIVILEGED: Self = Self::Zero;
    /// LEAST_PRIVILEGED returns the highest VMPL ring (the lowest privilege level)
    pub const LEAST_PRIVILEGED: Self = Self::Three;

    /// INT_MIN returns the lowest VMPL ring (the highest privilege level)
    pub const INT_MIN: Self = Self::MOST_PRIVILEGED;
    /// INT_MAX returns the highest VMPL ring (the least privilege level)
    pub const INT_MAX: Self = Self::LEAST_PRIVILEGED;
}

impl TryFrom<u8> for VMPrivilegeLevel {
    type Error = std::io::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => std::result::Result::Ok(Self::Zero),
            1 => std::result::Result::Ok(Self::One),
            2 => std::result::Result::Ok(Self::Two),
            3 => std::result::Result::Ok(Self::Three),
            other => std::result::Result::Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid TSM Privilege Level: {}", other),
            )),
        }
    }
}

impl std::fmt::Display for VMPrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u8) // Prints the u8 value, or map to text names
    }
}

/// get_privlevel_floor returns the minimum permissible TSM Privilege level value that can be set for the TSM report at the given path.
///
/// This is equivilant to reading the TSM ABI attribute @privlevel_floor.
pub fn get_privlevel_floor(report_path: &Path) -> Result<VMPrivilegeLevel, TsmReportError> {
    trace!(
        "Reading privlevel_floor for tsm report {:?}...",
        report_path
    );
    std::fs::read(report_path.join("privlevel_floor"))
        .map_err(|e| TsmReportError::Access("privlevel_floor", e))
        .and_then(|buf| {
            String::from_utf8(buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                .and_then(|s| {
                    s.parse::<u8>()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })
                .map_err(|e| TsmReportError::Access("privlevel_floor", e))
        })
        .and_then(|lvl| {
            lvl.try_into()
                .map_err(|e| TsmReportError::Access("privlevel_floor", e))
        })
}

/// set_privlevel sets the privilege level for the Configfs-TSM Query, updating the generation of report in the kernel.
///
/// If successful, this operation also increments the expected generation of the TsmReportPath instance.
pub fn set_privlevel(
    tsm: &TsmReportPath,
    privlevel: VMPrivilegeLevel,
) -> Result<&TsmReportPath, TsmReportError> {
    let report_path = tsm.report_path();

    tsm.check_tsm_report_generation()?;

    std::fs::write(report_path.join("privlevel"), privlevel.to_string()).map_err(|e| {
        // Verify that the requested privilege level is within the bounds --
        //   Note that exceeding the bounds triggers an EINVAL from the Kernel (OS Error 22)

        // Check against the lowest allowed privlevel (tsm api @privlevel_floor)
        // Check against the highest allowed privlevel (tsm abi TSM_PRIVLEVEL_MAX = 3)
        error!(
            "Failed to write {:?} to privlevel: {}.",
            privlevel.to_string(),
            e
        );
        let privlevel_floor = match get_privlevel_floor(report_path) {
            Ok(floor) => floor,
            Err(privfloor_err) => return privfloor_err,
        };

        let valid_range = privlevel_floor..=VMPrivilegeLevel::INT_MAX;
        trace!("Extracted privlevel_floor: {privlevel_floor}. Checking if privlevel {privlevel} is within bounds ({valid_range:?})...");

        if valid_range.contains(&privlevel) {
            warn!(
                "Privlevel {privlevel} is within bounds, but writing to privlevel failed: {e}"
            );
            TsmReportError::Access("privlevel", e)
        } else {
            error!("Privlevel {privlevel} is out of bounds ({valid_range:?})");
            TsmReportError::PrivlevelInvalid(privlevel as u8, privlevel_floor as u8, e)
        }
    })?;
    debug!(
        "Successfully set privlevel for TSM report {:?} to {} ({:?})...",
        report_path,
        privlevel,
        privlevel.to_string()
    );
    tsm.increment_expected_generation();
    Ok(tsm)
}
