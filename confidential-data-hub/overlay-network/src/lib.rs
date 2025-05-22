//
// SPDX-License-Identifier: Apache-2.0
//

pub mod config;
pub mod error;
#[cfg(feature = "overlay-network")]
pub mod nebula;
#[cfg(feature = "overlay-network")]
use crate::config::NebulaConfig;
use crate::config::OverlayNetworkConfig;
#[cfg(feature = "overlay-network")]
use crate::nebula::NebulaMesh;
pub use error::*;
use log::info;

pub async fn init(
    _kbs_url: &str,
    _pod_name: String,
    _overlay_network_config: &OverlayNetworkConfig,
) -> Result<()> {
    #[cfg(feature = "overlay-network")]
    {
        info!("Initializing overlay network");
        // XXX nebula is the only overlay-network currently implemented
        if let Some(c) = &_overlay_network_config.nebula {
            let nc: NebulaConfig = NebulaConfig {
                lighthouse_pub_ip: c.lighthouse_pub_ip.clone(),
                lighthouse_overlay_ip: c.lighthouse_overlay_ip.to_string(),
                overlay_netmask: c.overlay_netmask.clone(),
            };
            let nm: NebulaMesh = NebulaMesh {
                pod_name: _pod_name,
                config: nc,
            };
            nm.init(_kbs_url.to_string()).await?;
            Ok(())
        } else {
            Err(OverlayNetworkError::Init(
                "Unexpected: NebulaConfig is None".to_string(),
            ))
        }
    }
    #[cfg(not(feature = "overlay-network"))]
    {
        info!("Overlay network not supported");
        Err(OverlayNetworkError::NotEnabled())
    }
}
