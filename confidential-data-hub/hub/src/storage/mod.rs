// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;
pub use error::*;
pub mod drivers;
pub mod volume_type;

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use tracing_subscriber::{fmt, EnvFilter};

    static INIT: Once = Once::new();

    pub fn init_tracing() {
        INIT.call_once(|| {
            fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_test_writer()
                .try_init()
                .ok();
        });
    }
}
