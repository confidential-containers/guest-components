// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    save_supported_attesters_for_runtime()
}

fn save_supported_attesters_for_runtime() -> std::io::Result<()> {
    let always_enabled_features = ["SAMPLE_ATTESTER", "SAMPLE_DEVICE_ATTESTER"];
    // Keep this list in sync with [features].all-attesters in this crate's Cargo.toml.
    let optional_features = [
        "TDX_ATTESTER",
        "SGX_ATTESTER",
        "AZ_SNP_VTPM_ATTESTER",
        "AZ_TDX_VTPM_ATTESTER",
        "SNP_ATTESTER",
        "SE_ATTESTER",
        "CCA_ATTESTER",
        "CSV_ATTESTER",
        "HYGON_DCU_ATTESTER",
        "TPM_ATTESTER",
        "NVIDIA_ATTESTER",
        "NVIDIA_DPU_ATTESTER",
    ];

    let enabled_features: Vec<&str> = always_enabled_features
        .into_iter()
        .chain(
            optional_features
                .into_iter()
                .filter(|feature| env::var_os(format!("CARGO_FEATURE_{feature}")).is_some()),
        )
        .map(|feature| feature.strip_suffix("_ATTESTER").unwrap_or(feature))
        .collect();

    let out_dir = env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR");
    let dest_path = Path::new(&out_dir).join("supported_attesters.rs");
    let mut f = File::create(dest_path)?;

    writeln!(f, "&{enabled_features:?}")
}
