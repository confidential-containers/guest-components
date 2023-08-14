// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{hub::Hub, Result};

#[cfg(feature = "sev")]
mod sev;

#[cfg(feature = "kbs")]
mod kbs;

impl Hub {
    pub(crate) async fn init(&mut self) -> Result<()> {
        #[cfg(feature = "sev")]
        {
            Self::init_sev().await?;
        }

        #[cfg(feature = "kbs")]
        {
            Self::init_kbs_resources().await?;
        }

        Ok(())
    }
}
