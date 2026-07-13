// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{hub::Hub, Result};

#[cfg(feature = "kbs")]
mod kbs;

impl Hub {
    pub(crate) async fn init(&mut self) -> Result<()> {
        #[cfg(feature = "kbs")]
        {
            self.init_kbs_resources().await?;
        }

        Ok(())
    }
}
