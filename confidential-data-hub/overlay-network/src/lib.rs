//
// SPDX-License-Identifier: Apache-2.0
//

pub mod nebula;
pub mod config;
pub mod error;
use crate::config::OverlayNetworkConfig;
#[cfg(feature = "overlay-network")]
use crate::nebula::{NebulaMesh, NebulaConfig};
pub use error::*;
use log::info;

pub async fn init(_kbs_url: &String, _pod_name: String, _overlay_network_config: &OverlayNetworkConfig) -> Result<()> {
    #[cfg(feature = "overlay-network")]
    {
        // XXX nebula is the only overlay-network currently implemented
        let nm: NebulaMesh = NebulaMesh {
            pod_name: _pod_name,
            lighthouse_ip: _overlay_network_config.nebula.lighthouse_pub_ip,
            overlay_netmask: _overlay_network_config.nebula.overlay_netmask,
        };
        nm.init(_kbs_url).await?;
        Ok(())
    }
    #[cfg(not(feature = "overlay-network"))]
    {
        info!("overlay network not supported ");
        Err(OverlayNetworkError::NotEnabled())
    }
}
