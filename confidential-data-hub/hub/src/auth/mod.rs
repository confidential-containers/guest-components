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
            use log::{info, warn};
            match attestation_agent::aa_kbc_params::get_params().await {
                Ok(aa_kbc_params) => {
                    if aa_kbc_params.kbc() == "online_sev_kbc" {
                        info!("online_sev_kbc used. Start to initialize sev.");
                        Self::init_sev().await?;
                    }
                }
                Err(e) => warn!("Get `aa_kbc_params` failed. Skip initialize sev. {e:?}"),
            };
        }

        #[cfg(feature = "kbs")]
        {
            Self::init_kbs_resources().await?;
        }

        Ok(())
    }
}
