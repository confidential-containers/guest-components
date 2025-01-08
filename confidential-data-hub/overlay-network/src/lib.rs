//
// SPDX-License-Identifier: Apache-2.0
//

pub mod overlay_network;
pub mod error;
#[cfg(feature = "overlay-network")]
use crate::overlay_network::nebula::NebulaMesh;
pub use error::*;
use log::info;

pub async fn init(_pod_name: String, _lighthouse_pub_ip: String) -> Result<()> {
    #[cfg(feature = "overlay-network")]
    {
        let nm: NebulaMesh = NebulaMesh {
            pod_name: pod_name,
            lighthouse_ip: lighthouse_pub_ip,
        };
        nm.init().await?;
        Ok(())
    }
    #[cfg(not(feature = "overlay-network"))]
    {
        info!("overlay network not supported ");
        Err(OverlayNetworkError::NotEnabled())
    }
}
