//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use serde::Deserialize;

#[derive(Default, Clone, Deserialize, Debug, PartialEq)]
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
            return Err(anyhow!(
                "overlay_network is disabled but nebula fields are set"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct NebulaConfig {
    pub lighthouse_pub_ip: String,
    pub lighthouse_overlay_ip: String,
    pub overlay_netmask: String,
}
