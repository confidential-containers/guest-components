// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

pub fn get_version_message(header: &'static str) -> &'static str {
    static VERSION_MESSAGE: OnceLock<String> = OnceLock::new();
    VERSION_MESSAGE
        .get_or_init(|| {
            format!(
                "{header}\nsupported attesters: {}\n{}",
                attester::get_supported_attesters().join(", "),
                include_str!(concat!(env!("OUT_DIR"), "/token_plugins"))
            )
        })
        .as_str()
}
