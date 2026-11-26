// SPDX-License-Identifier: Apache-2.0

use attester::Attesters;
use shadow_rs::shadow;
use std::sync::OnceLock;

shadow!(build);

pub const BUILD_TIME: &str = build::BUILD_TIME;

pub fn get_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let dirty_suffix = if build::GIT_CLEAN { "" } else { " (dirty)" };
        let token_plugins: &[&str] = &[
            #[cfg(feature = "kbs")]
            "KBS",
            #[cfg(feature = "coco_as")]
            "COCO_AS",
        ];

        format!(
            "{}-{}{dirty_suffix}\n\nsupported attesters: {}\ntoken plugins: {}",
            build::LAST_TAG,
            build::SHORT_COMMIT,
            Attesters::get().get_attester_names().join(", "),
            token_plugins.join(", "),
        )
    })
}
