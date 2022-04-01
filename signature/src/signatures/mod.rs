// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod sigstore;
mod verify;

pub use sigstore::SigstoreConfig;
pub use sigstore::SIGSTORE_CONFIG_DIR;
pub use sigstore::{format_sigstore_name, get_sigs_from_specific_sigstore};
pub use verify::verify_sig_and_extract_payload;
