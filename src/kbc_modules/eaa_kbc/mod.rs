// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
use anyhow::*;
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

pub mod protocol;
pub mod rats_tls;
use protocol::*;

#[derive(Serialize, Deserialize, Debug)]
struct AnnotationPacket {
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub algorithm: String,
    pub key_length: u16,
}

pub struct EAAKbc {
    pub kbs_uri: String,
    pub protocol_version: String,
    pub algorithm: String,
    pub key_length: u16,
    pub tcp_stream: Option<TcpStream>,
    pub tls_handle: Option<rats_tls::RatsTls>,
}

impl KbcInterface for EAAKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_addr".to_string(), self.kbs_uri.clone());
        kbs_info.insert(
            "protocol_version".to_string(),
            self.protocol_version.clone(),
        );
        Ok(KbcCheckInfo { kbs_info: kbs_info })
    }

    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
        debug!("EAA KBC decrypt_payload() is called!");
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)?;
        self.algorithm = annotation_packet.algorithm;
        self.key_length = annotation_packet.key_length;
        if self.tcp_stream.is_none() {
            debug!("First request, connecting KBS...");
            self.establish_new_kbs_connection()?;
            debug!("connect success! TLS is established!");
        }

        debug!("start decrypt...");
        let decrypted_payload = self.kbs_decrypt_payload(
            annotation_packet.wrapped_data,
            annotation_packet.kid,
            annotation_packet.iv,
        )?;
        debug!("decrypted success!");
        Ok(decrypted_payload)
    }
}

impl EAAKbc {
    pub fn new(kbs_uri: String) -> EAAKbc {
        EAAKbc {
            kbs_uri: kbs_uri,
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
        let request = VersionRequest::new();
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let recv_string: String = self.kbs_trans_and_recv(trans_data, "Version")?;
        let response: VersionResponse =
            serde_json::from_str::<VersionResponse>(recv_string.as_str())?;

        match response.status.as_str() {
            "OK" => return Ok(response.version),
            "Fail" => return Err(anyhow!("The VersionResponse status is 'Fail'!")),
            _ => return Err(anyhow!("Can't understand the VersionResponse status!")),
        }
    }

    fn kbs_decrypt_payload(
        &mut self,
        encrypted_payload: Vec<u8>,
        key_id: String,
        iv: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let blob = Blob {
            kid: key_id.clone(),
            encrypted_data: base64::encode(&encrypted_payload),
            algorithm: "AES".to_string(),
            key_length: 256,
            iv: base64::encode(&iv),
        };
        let request = DecryptionRequest::new(blob);
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();

        let recv_string: String = self.kbs_trans_and_recv(trans_data, "Decryption")?;
        let response: DecryptionResponse =
            serde_json::from_str::<DecryptionResponse>(recv_string.as_str())?;

        let payload_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => return Err(anyhow!(format!("Verdictd: {}", response.error.unwrap()))),
            _ => return Err(anyhow!("Can't understand the DecryptionResponse status!")),
        };

        if let Some(hashmap_content) = payload_hashmap {
            let encrypted_payload_string = base64::encode(&encrypted_payload);
            let decrypted_payload_string = hashmap_content.get(&encrypted_payload_string).ok_or(anyhow!(
                "There is no field matching the encrypted payload in the data field of DecryptionResponse"
            ))?;
            let decrypted_payload = base64::decode(decrypted_payload_string)?;
            return Ok(decrypted_payload);
        } else {
            return Err(anyhow!(
                "DecryptionResponse status is OK but the data is null!"
            ));
        }
    }

    fn kbs_trans_and_recv(&mut self, trans_data: &[u8], error_info: &str) -> Result<String> {
        debug!("Transmit: {}", String::from_utf8(trans_data.to_vec())?);
        self.tls_handle
            .as_ref()
            .ok_or(anyhow!("Missing TLS handle"))?
            .transmit(trans_data)
            .map_err(|e| {
                error!("Transmit {} failed", error_info);
                anyhow!(format!("Something wrong when transmit, error code: {}", e))
            })?;

        // At present, the returned packets of the verdictd server is small,
        // and the size of these packets does not exceed 4096 bytes (we have tested),
        // them will not be divided into multiple packets (if this happen, an error will be reported).
        let mut buffer = [0u8; 4096];
        let len_recv = self
            .tls_handle
            .as_ref()
            .ok_or(anyhow!("Missing TLS handle"))?
            .receive(&mut buffer)
            .map_err(|e| {
                error!("Transmit {} failed", error_info);
                anyhow!(format!("Something wrong when revieve, error code: {}", e))
            })?;

        let recv_string: String = String::from_utf8(buffer[..len_recv].to_vec())?;
        debug!("Recieved: {}", recv_string);

        Ok(recv_string)
    }
}
