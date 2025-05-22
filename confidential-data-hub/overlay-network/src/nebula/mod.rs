//
// SPDX-License-Identifier: Apache-2.0
//

pub mod config_templates;

use crate::nebula::config_templates::WORKER_CONFIG_TEMPLATE;
use crate::{OverlayNetworkError, Result};
use kms::{Annotations, ProviderSettings};
use log::debug;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{AddressFamily, SockaddrLike};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yml;
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;

use crate::config::NebulaConfig;

pub struct NebulaMesh {
    pub pod_name: String,
    pub config: NebulaConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NebulaPluginResponse {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

const NEBULA_BIN: &str = "/opt/overlay-network/nebula";
const LIGHTHOUSE_PORT: u32 = 4242; // sync with WORKER_CONFIG_TEMPLATE
const CA_CERT_PATH: &str = "/tmp/nebula/ca.crt";
const POD_CERT_PATH: &str = "/tmp/nebula/pod.crt";
const POD_KEY_PATH: &str = "/tmp/nebula/pod.key";
const WORKER_CONFIG_PATH: &str = "/tmp/nebula/config.yaml";

impl NebulaMesh {
    /// Initialize a nebula mesh. The general approach is as follows:
    /// - Calculate what the mesh IP will be for this worker.
    /// - Ask trustee for its nebula credentials
    /// - Start the nebula daemon.
    pub async fn init(&self, kbs_url: String) -> Result<()> {
        let kbs_url: Ipv4Addr = kbs_url.parse()?;
        let response: NebulaPluginResponse = self.request_key_and_certs(kbs_url).await?;
        self.write_key_and_certs_to_file(response)?;
        self.write_worker_config_to_file()?;
        debug!("Launching nebula daemon");
        Command::new(NEBULA_BIN)
            .arg("-config")
            .arg(WORKER_CONFIG_PATH)
            .spawn()
            .expect("nebula command failed to start");

        Ok(())
    }

    /// The nebula daemon requires a CA cert, pod cert, and pod key. The
    /// nebula-plugin in the trustee provides these, so this function queries
    /// it with the necessary parameters.
    async fn request_key_and_certs(&self, kbs_url: Ipv4Addr) -> Result<NebulaPluginResponse> {
        let mesh_ip = self.generate_mesh_ip()?;
        let overlay_netmask: Ipv4Addr = self.config.overlay_netmask.parse()?;
        let prefix_len: u32 = self.netmask_to_prefix_len(overlay_netmask);
        let neb_cred_uri: String = format!(
            "kbs://{}:8080/plugin\
            /nebula-ca/credential\
            ?name={}\
            &ip={}/{}",
            kbs_url, self.pod_name, mesh_ip, prefix_len
        )
        .to_owned();

        let client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| OverlayNetworkError::KbsClient { source: e })?;
        debug!("Requesting overlay network creds");
        let response = client
            .get_secret(&neb_cred_uri, &Annotations::default())
            .await
            .map_err(|e| OverlayNetworkError::GetSecret { source: e })?;
        Ok(serde_json::from_slice(&response)?)
    }

    /// The nebula daemon expects its key and certs to be on disk, so we
    /// write them to file here.
    fn write_key_and_certs_to_file(&self, key_and_certs: NebulaPluginResponse) -> Result<()> {
        fs::create_dir("/tmp/nebula")?;
        fs::write(POD_KEY_PATH, key_and_certs.node_key)?;
        fs::write(CA_CERT_PATH, key_and_certs.ca_crt)?;
        fs::write(POD_CERT_PATH, key_and_certs.node_crt)?;
        Ok(())
    }

    /// The nebula daemon expects its config to be on disk, so we write it
    /// to file here. This function is also responsible for tidying up any
    /// parts of the config template (e.g. the lighthouse info).
    fn write_worker_config_to_file(&self) -> Result<()> {
        let static_host_map_str = format!(
            "\"{}\": [\"{}:{}\"]",
            self.config.lighthouse_overlay_ip, self.config.lighthouse_pub_ip, LIGHTHOUSE_PORT
        );
        let static_host_map = serde_yml::from_str::<Value>(&static_host_map_str)?;
        let mut rule_file = serde_yml::from_str::<Value>(WORKER_CONFIG_TEMPLATE)?;
        *rule_file.get_mut("static_host_map").unwrap() = static_host_map;
        rule_file
            .get_mut("lighthouse")
            .unwrap()
            .get_mut("hosts")
            .unwrap()[0] = self.config.lighthouse_overlay_ip.to_string().into();

        let fp = fs::File::create(WORKER_CONFIG_PATH).expect("error creating worker config file");
        serde_yml::to_writer(fp, &rule_file)?;
        Ok(())
    }

    /// Read /proc/net/route to get the default gateway's interface,
    /// e.g. "eth0".
    /// TODO This is brittle. Is there a reason to not use procfs::net here?
    fn get_iface_of_default_gateway(&self) -> Result<String> {
        let binding = fs::read_to_string("/proc/net/route")?;
        let s: Vec<&str> = binding.split('\n').collect();
        let mut iface: &str = "";
        for part in s {
            let tokens: Vec<&str> = part.split_whitespace().collect();
            iface = tokens[0];
            let destination: &str = tokens[1];
            // FIXME ? Should mask also be checked?
            let _mask: &str = tokens[7];
            if destination == "00000000" {
                break;
            }
        }
        Ok(iface.to_string())
    }

    /// Get the IP address and netmask for some iface. This relies on the nix
    /// library's getifaddrs support.
    fn get_ip_and_mask(&self, iface: &String) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let addrs = getifaddrs().map_err(|e| {
            OverlayNetworkError::IfaceDetails(format!("getifaddrs returned error: {}", e))
        })?;
        for ifaddr in addrs {
            if ifaddr.interface_name == *iface {
                let Some(address) = ifaddr.address else {
                    continue;
                };
                let Some(netmask) = ifaddr.netmask else {
                    continue;
                };
                if let Some(AddressFamily::Inet) = address.family() {
                    // ipv4
                    let Some(address) = address.as_sockaddr_in() else {
                        continue;
                    };
                    let Some(netmask) = netmask.as_sockaddr_in() else {
                        continue;
                    };
                    return Ok((address.ip(), netmask.ip()));
                }
            }
        }
        Err(OverlayNetworkError::IfaceDetails(format!(
            "Unable to find address and mask for {}",
            iface
        )))
    }

    /// Convert a netmask to its prefix length (e.g. convert 255.255.255.0 to 24)
    fn netmask_to_prefix_len(&self, netmask: Ipv4Addr) -> u32 {
        netmask
            .octets()
            .iter()
            .fold(0, |count, oct| count + oct.count_ones())
    }

    /// Form the IP address that this worker will have in the mesh. This is
    /// done by combining the upper bits of the (known, predetermined)
    /// lighthouse overlay IP with the lower bits of the (dynamic) k8s-assigned
    /// IP of the worker's default interface.
    /// TODO It is an error for the k8s netmask to be smaller than the mesh (i.e.
    ///      for the addressable range to be larger than the mesh's). This could
    ///      cause IP assignment collisions for the mesh, even when using a benign
    ///      k8s.
    /// TODO Similar: Need to handle collisions in the case of a malicious k8s.
    ///      Or, at least, document behavior (e.g. DoS).
    /// TODO Do not collide on the lighthouse IP address.
    fn generate_mesh_ip(&self) -> Result<Ipv4Addr> {
        let iface: String = self.get_iface_of_default_gateway()?;
        let (iface_ip, iface_mask) = self.get_ip_and_mask(&iface)?;
        let overlay_netmask: Ipv4Addr = self.config.overlay_netmask.parse()?;
        let lighthouse_overlay_ip: Ipv4Addr = self.config.lighthouse_overlay_ip.parse()?;
        if iface_mask != overlay_netmask {
            return Err(OverlayNetworkError::NetmaskMismatch(format!(
                "worker netmask ({}) and lighthouse netmask ({}) do not match",
                iface_mask, overlay_netmask
            )));
        }
        let mesh_ip = (lighthouse_overlay_ip & overlay_netmask) | (iface_ip & !overlay_netmask);
        Ok(mesh_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(255, 255, 255, 255, 32)]
    #[case(255, 255, 255, 0, 24)]
    #[case(0, 0, 0, 0, 0)]
    #[case(255, 255, 254, 0, 23)]
    #[case(255, 255, 255, 8, 25)]
    fn test_netmask_to_prefix_len(
        #[case] a: u8,
        #[case] b: u8,
        #[case] c: u8,
        #[case] d: u8,
        #[case] prefix_len: u32,
    ) {
        let ip: Ipv4Addr = Ipv4Addr::new(a, b, c, d);
        let nm: NebulaMesh = NebulaMesh {
            pod_name: "".to_string(),
            config: NebulaConfig {
                lighthouse_pub_ip: "".to_string(),
                lighthouse_overlay_ip: "".to_string(),
                overlay_netmask: "".to_string(),
            },
        };
        let rv: u32 = nm.netmask_to_prefix_len(ip);
        assert_eq!(rv, prefix_len);
    }
}
