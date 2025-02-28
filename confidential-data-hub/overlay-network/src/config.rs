//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use serde::Deserialize;
use crate::nebula::NebulaConfig;

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct OverlayNetworkConfig {
    pub enable: bool,
    pub nebula: Option<NebulaConfig>,
}

impl OverlayNetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enable && self.nebula.is_none() {
            return Err(anyhow!("overlay_network is enabled without nebula fields"));
        }
        if !self.enable && self.nebula.is_some() {
            return Err(anyhow!("overlay_network is disabled but nebula fields are set"));
        }
        Ok(())
    }
}
                                                                                                         impl Default for OverlayNetworkConfig {
    fn default() -> Self {
        OverlayNetworkConfig {
            enable: false,
            nebula: None,
        }
    }
}
