// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface, ResourceDescription};
use anyhow::*;
use async_trait::async_trait;
use log::*;
use std::collections::HashMap;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

pub mod protocol;
pub mod rats_tls;
use protocol::*;

use super::AnnotationPacket;

// Verdictd is the EAA KBS's name,
// the repo is here: https://github.com/inclavare-containers/verdictd
const EAA_KBS_NAME: &str = "Verdictd";

const DEFAULT_RECV_BYTES_SIZE: usize = 4096;

pub struct EAAKbc {
    pub kbs_uri: String,
    pub protocol_version: String,
    pub algorithm: String,
    pub key_length: u16,
    pub tcp_stream: Option<TcpStream>,
    pub tls_handle: Option<rats_tls::RatsTls>,
}

#[async_trait]
impl KbcInterface for EAAKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_addr".to_string(), self.kbs_uri.clone());
        kbs_info.insert(
            "protocol_version".to_string(),
            self.protocol_version.clone(),
        );
        Ok(KbcCheckInfo { kbs_info })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        debug!("EAA KBC decrypt_payload() is called");

        if self.tcp_stream.is_none() {
            debug!("First request, connecting KBS...");
            self.establish_new_kbs_connection()?;
            debug!("connect success! TLS is established");
        }

        debug!("start decrypt...");
        let decrypted_payload = self.kbs_decrypt_payload(
            base64::decode(annotation_packet.wrapped_data)?,
            annotation_packet.kid,
            base64::decode(annotation_packet.iv)?,
        )?;
        debug!("decrypted success");
        Ok(decrypted_payload)
    }

    async fn get_resource(&mut self, description: &str) -> Result<Vec<u8>> {
        if self.tcp_stream.is_none() {
            debug!("First request, connecting KBS...");
            self.establish_new_kbs_connection()?;
            debug!("connect success! TLS is established");
        }

        self.kbs_get_resource(description)
    }
}

impl EAAKbc {
    pub fn new(kbs_uri: String) -> EAAKbc {
        EAAKbc {
            kbs_uri,
            protocol_version: String::new(),
            algorithm: String::new(),
            key_length: 0,
            // kek_cache: HashMap::new(),
            tcp_stream: None,
            tls_handle: None,
        }
    }

    fn establish_new_kbs_connection(&mut self) -> Result<()> {
        debug!("create RATS TLS handle...");
        self.tls_handle =
            Some(rats_tls::RatsTls::new().map_err(|e| anyhow!("create rats_tls failed!:{:?}", e))?);

        self.tcp_stream = Some(TcpStream::connect(&self.kbs_uri)?);

        debug!("start negotiate (attestation) ...");
        self.tls_handle
            .as_ref()
            .unwrap()
            .negotiate(self.tcp_stream.as_ref().unwrap().as_raw_fd())
            .map_err(|e| anyhow!("Negotiate Failed!:{:?}", e))?;

        self.protocol_version = self.kbs_query_version()?;

        Ok(())
    }

    fn kbs_query_version(&mut self) -> Result<String> {
        let request = VersionRequest::default();
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();

        let recv_string: String =
            self.kbs_trans_and_recv(trans_data, DEFAULT_RECV_BYTES_SIZE, "Version")?;
        let response: VersionResponse =
            serde_json::from_str::<VersionResponse>(recv_string.as_str())?;

        match response.status.as_str() {
            "OK" => Ok(response.version),
            "Fail" => Err(anyhow!("The VersionResponse status is Fail")),
            _ => Err(anyhow!("Cannot understand the VersionResponse status")),
        }
    }

    fn kbs_decrypt_payload(
        &mut self,
        encrypted_payload: Vec<u8>,
        key_id: String,
        iv: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let blob = Blob {
            kid: key_id,
            encrypted_data: base64::encode(&encrypted_payload),
            algorithm: "AES".to_string(),
            key_length: 256,
            iv: base64::encode(iv),
        };
        let request = DecryptionRequest::new(blob);
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();

        let recv_string: String =
            self.kbs_trans_and_recv(trans_data, DEFAULT_RECV_BYTES_SIZE, "Decryption")?;
        let response: DecryptionResponse =
            serde_json::from_str::<DecryptionResponse>(recv_string.as_str())?;

        let payload_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => {
                return Err(anyhow!(format!(
                    "{}: {}",
                    EAA_KBS_NAME,
                    response.error.unwrap()
                )))
            }
            _ => return Err(anyhow!("Cannot understand the DecryptionResponse status")),
        };

        if let Some(hashmap_content) = payload_hashmap {
            let encrypted_payload_string = base64::encode(&encrypted_payload);
            let decrypted_payload_string = hashmap_content.get(&encrypted_payload_string).ok_or_else(|| anyhow!(
                "There is no field matching the encrypted payload in the data field of DecryptionResponse"
            ))?;
            let decrypted_payload = base64::decode(decrypted_payload_string)?;
            Ok(decrypted_payload)
        } else {
            Err(anyhow!(
                "DecryptionResponse status is OK but the data is null"
            ))
        }
    }

    fn kbs_get_resource(&mut self, description: &str) -> Result<Vec<u8>> {
        let desc: ResourceDescription = serde_json::from_str::<ResourceDescription>(description)?;

        let command = format!("Get {}", desc.name.as_str());
        let request = GetResourceRequest::new(&command, desc.optional.clone());
        let resource_info = self.kbs_get_resource_info(desc.name.as_str())?;

        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let buffer_size: usize = resource_info.base64size.parse::<usize>()?;

        let recv_string: String =
            self.kbs_trans_and_recv(trans_data, buffer_size, "Get Resource")?;

        let data_bytes = base64::decode(recv_string)?;

        if let Result::Ok(data_str) = std::str::from_utf8(&data_bytes) {
            if let Result::Ok(err_info) = serde_json::from_str::<GetResourceErrorInfo>(data_str) {
                return Err(anyhow!(
                    "{}: The resource data is null, error reason: {}.",
                    EAA_KBS_NAME,
                    err_info.error
                ));
            }
        }

        Ok(data_bytes)
    }

    fn kbs_get_resource_info(&mut self, resource_name: &str) -> Result<ResourceInfo> {
        let request = GetResourceInfoReq::new(resource_name);
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();

        let recv_string: String =
            self.kbs_trans_and_recv(trans_data, DEFAULT_RECV_BYTES_SIZE, "Get Resource Info")?;

        let response = serde_json::from_str::<GetResourceInfoResponse>(recv_string.as_str())?;

        match response.status.as_str() {
            "OK" => response
                .data
                .ok_or_else(|| anyhow!("{}: Resource info payload is null", EAA_KBS_NAME)),
            "Fail" => Err(anyhow!(format!(
                "{}: {}",
                EAA_KBS_NAME,
                response.error.unwrap()
            ))),
            _ => Err(anyhow!(
                "Cannot understand the GetResourceInfoResponse status"
            )),
        }
    }

    fn kbs_trans_and_recv(
        &mut self,
        trans_data: &[u8],
        recv_size: usize,
        error_info: &str,
    ) -> Result<String> {
        if trans_data.to_vec().is_empty() || recv_size == 0 {
            return Err(anyhow!(
                "Transmit data cannot be empty and recieve buffer size cannot be zero."
            ));
        }
        debug!("Transmit: {}", String::from_utf8(trans_data.to_vec())?);
        self.tls_handle
            .as_ref()
            .ok_or_else(|| anyhow!("Missing TLS handle"))?
            .transmit(trans_data)
            .map_err(|e| {
                error!("Transmit {} failed", error_info);
                anyhow!(format!("Something wrong when transmit, error code: {}", e))
            })?;

        let mut recv_buffer = vec![0u8; rats_tls::MAX_FRAG_LENGTH];
        let mut recv_res = vec![];
        let mut len_recv = 0;

        while len_recv < recv_size {
            let len_single = self
                .tls_handle
                .as_ref()
                .ok_or_else(|| anyhow!("Missing TLS handle"))?
                .receive(&mut recv_buffer)
                .map_err(|e| {
                    error!("Transmit {} failed", error_info);
                    anyhow!(format!("Something wrong when revieve, error code: {}", e))
                })?;

            recv_res.append(&mut recv_buffer[..len_single].to_vec());
            if len_single < rats_tls::MAX_FRAG_LENGTH {
                break;
            };
            len_recv += len_single;
        }

        let recv_string: String = String::from_utf8(recv_res)?;
        debug!("Recieved: {}", recv_string);

        Ok(recv_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_kbc() {
        let kbs_addr = "127.0.0.1:30000".to_string();
        let kbs_protocol_version = "0.1.0".to_string();

        let eaa_kbc = EAAKbc {
            kbs_uri: kbs_addr.clone(),
            protocol_version: kbs_protocol_version.clone(),
            algorithm: String::new(),
            key_length: 32,
            tcp_stream: None,
            tls_handle: None,
        };

        let check_res = eaa_kbc.check();
        assert!(check_res.is_ok());

        let info = check_res.unwrap().kbs_info;

        assert_eq!(info.get("kbs_addr").unwrap(), &kbs_addr);
        assert_eq!(info.get("protocol_version").unwrap(), &kbs_protocol_version);
    }
}
