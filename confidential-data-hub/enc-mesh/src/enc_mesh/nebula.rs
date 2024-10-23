//
// SPDX-License-Identifier: Apache-2.0
//

use std::{str::FromStr};

use serde::{Serialize, Deserialize};
use serde_json::Value;

use std::process::Command;

use kms::{Annotations, ProviderSettings};
use std::fs::{self};

use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{SockaddrStorage, SockaddrLike, AddressFamily};
use std::net::{Ipv4Addr};

use serde_yml;

use crate::{Result, EncMeshError};


pub struct NebulaMesh;

// FIXME This should be a shared struct, if possible, with trustee's nebula
//       plugin. It's that plugin's custom protocol.
#[derive(Debug, Serialize, Deserialize)]
pub struct NebulaPluginResponse {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}


const CA_CERT_PATH: &str  = "/tmp/nebula/ca.crt";
const POD_CERT_PATH: &str = "/tmp/nebula/pod.crt";
const POD_KEY_PATH: &str  = "/tmp/nebula/pod.key";

// FIXME the LIGHTHOUSE_CONFIG_PATH and the WORKER_CONFIG_TEMPLATE_PATH are
// determined at image/rootfs build time. Those values must be consistent
// with whatever is here.
const LIGHTHOUSE_CONFIG_PATH: &str      = "/opt/enc-mesh/lighthouse-config.yaml";
const WORKER_CONFIG_TEMPLATE_PATH: &str = "/opt/enc-mesh/config.yaml";
const WORKER_CONFIG_PATH: &str          = "/tmp/nebula/config.yaml";

// FIXME These should be configurable
const LIGHTHOUSE_IP: Ipv4Addr   = Ipv4Addr::new(192, 168, 100, 100);
const LIGHTHOUSE_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);


impl NebulaMesh {

    /// Set up a nebula mesh. The general approach is as follows:
    /// - Calculate what the mesh IP will be for this worker.
    /// - Ask trustee for its nebula credentials
    /// - Start the nebula daemon.
    pub async fn set_up(&self,
                        pod_name: String,
                        lighthouse_pub_ip: String) -> Result<()> {
        let is_lighthouse: bool = lighthouse_pub_ip.is_empty();
        let mut mesh_ip = LIGHTHOUSE_IP;
        if !is_lighthouse {
            mesh_ip = self.generate_mesh_ip()?;
        }

        // FIXME: kbs hard-coded to localhost is wrong. This should be based on
        //        ResourceUri? Where does it come from?
        let prefix_len: u32 = self.netmask_to_prefix_len(LIGHTHOUSE_MASK);
        let neb_cred_uri: String = format!("kbs://127.0.0.1:8080/plugin/\
                                               nebula/credential\
                                               ?ip[ip]={}\
                                               &ip[netbits]={}\
                                               &name={}",
                                               mesh_ip, prefix_len, pod_name).to_owned();

        let client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| EncMeshError::KbsClient{ source: e })?;
        let response = client
            .get_secret(&neb_cred_uri, &Annotations::default())
            .await
            .map_err(|e| EncMeshError::GetSecret{ source: e })?;
        let response: NebulaPluginResponse = serde_json::from_slice(&response)?;

        fs::create_dir("/tmp/nebula")?;
        fs::write(CA_CERT_PATH, response.ca_crt)?;
        fs::write(POD_CERT_PATH, response.node_crt)?;
        fs::write(POD_KEY_PATH, response.node_key)?;

        let mut which_config = LIGHTHOUSE_CONFIG_PATH;
        if !is_lighthouse {
            which_config = WORKER_CONFIG_PATH;
            let content = std::fs::read_to_string(WORKER_CONFIG_TEMPLATE_PATH)?;
            let mut rule_file = serde_yml::from_str::<Value>(&content)?;
            // FIXME ? should the 4242 port be hard-coded
            let static_host_map_str = format!("\"{}\": [\"{}:4242\"]",
              LIGHTHOUSE_IP, lighthouse_pub_ip);
            let static_host_map = serde_yml::from_str::<Value>(&static_host_map_str)?;

            // FIXME these are Option<>s
            *rule_file.get_mut("static_host_map").unwrap() = static_host_map.into();
            rule_file.get_mut("lighthouse").unwrap().get_mut("hosts").unwrap()[0]
              = format!("{}", LIGHTHOUSE_IP).into();

            let fp = std::fs::File::create(which_config).expect("error creating file");
            serde_yml::to_writer(fp, &rule_file)?;
        }

        Command::new("/opt/enc-mesh/nebula")
            .arg("-config")
            .arg(which_config)
            .spawn()
            .expect("nebula command failed to start");

        Ok(())
    }


    /// Read /proc/net/route to get the default gateway's interface,
    /// e.g. "eth0".
    /// TODO This is brittle. Is there a reason to not use procfs::net here?
    fn get_iface_of_default_gateway(&self) -> Result<String> {
        let binding = fs::read_to_string("/proc/net/route")?;
        let s: Vec<&str> = binding.split("\n").collect();
        let mut iface: &str = "";
        for part in s {
            let tokens: Vec<&str> = part.split_whitespace().collect();
            iface = tokens[0];
            let destination: &str = tokens[1];
            let mask: &str = tokens[7];
            // FIXME ? Should mask also be checked?
            if destination == "00000000" {
                break;
            }
        }
        Ok(iface.to_string())
    }


    /// Get the IP address and netmask for some iface. This relies on the nix
    /// library's getifaddrs support.
    fn get_ip_and_mask(&self, iface: &String) -> Result<(Ipv4Addr, Ipv4Addr)> {
        let addrs = getifaddrs().map_err(|e| EncMeshError::IfaceDetails(format!(
          "getifaddrs returned error: {}", e)))?;
        for ifaddr in addrs {
            if ifaddr.interface_name == *iface {
                let Some(address) = ifaddr.address else { continue };
                let Some(netmask) = ifaddr.netmask else { continue };
                if let Some(AddressFamily::Inet) = address.family() { // ipv4
                    println!("interface {} address {} netmask {}",
                             ifaddr.interface_name, address, netmask);
                    let Some(address) = address.as_sockaddr_in() else { continue };
                    let Some(netmask) = netmask.as_sockaddr_in() else { continue };
                    return Ok((address.ip(), netmask.ip()));
                }
            }
        }
        return Err(EncMeshError::IfaceDetails(format!("Unable to find address \
          and mask for {}", iface)));
    }


    /// Convert a netmask to its prefix length (e.g. convert 255.255.255.0 to 24)
    fn netmask_to_prefix_len(&self, netmask: Ipv4Addr) -> u32 {
        netmask.octets().iter().fold(0, |count, oct| count + oct.count_ones())
    }


    /// Form the IP address that this worker will have in the mesh. This is done
    /// by combining the upper bits of the (known, predetermined) lighthouse IP
    /// with the lower bits of the (dynamic) k8s-assigned IP of the worker's
    /// default interface.
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
        if iface_mask != LIGHTHOUSE_MASK {
            return Err(EncMeshError::NetmaskMismatch(format!("worker netmask \
              ({}) and lighthouse netmask ({}) do \
              not match", iface_mask, LIGHTHOUSE_MASK)));
        }
        let mesh_ip =   (LIGHTHOUSE_IP &  LIGHTHOUSE_MASK)
                      | (iface_ip      & !LIGHTHOUSE_MASK);
        Ok(mesh_ip)
    }

}






#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use nix::sys::socket::SockaddrIn;

    use nix::libc::in_addr;

    #[rstest]
    #[case(255, 255, 255, 255, 32)]
    #[case(255, 255, 255,   0, 24)]
    #[case(  0,   0,   0,   0,  0)]
    #[case(255, 255, 254,   0, 23)]
    #[case(255, 255, 255,   8, 25)]
    fn test_netmask_to_prefix_len(#[case] a: u8,
                                  #[case] b: u8,
                                  #[case] c: u8,
                                  #[case] d: u8,
                                  #[case] prefix_len: u32) {
        let ip: Ipv4Addr   = Ipv4Addr::new(a, b, c, d);
        let nm: NebulaMesh = NebulaMesh {};
        let rv: u32 = nm.netmask_to_prefix_len(ip);
        assert_eq!(rv, prefix_len);
    }

}
