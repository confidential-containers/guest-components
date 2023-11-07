// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use log::{debug, info};

use crate::plugins::init_image_encrypter;

struct InputParams {
    /// Specify the KEK of this image. keyid field will be
    /// included in AnnotationPacket. For example:
    /// `kbs:///default/key/test-tag`
    keyid: Option<String>,

    /// Specify the KEK to encrypted the image in local
    /// filesystem. This key will be read from fs and then
    /// used to encrypt the image. This key's length must
    /// be 32 bytes
    keypath: Option<String>,

    /// The KMS type to encrypt the image
    encrypter: String,
}

fn parse_input_params(input: &str) -> Result<InputParams> {
    let map: HashMap<&str, &str> = input
        .split("::")
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|field| field.split_once('='))
        .map(|(k, v)| (k, v))
        .collect();
    debug!("Get new request: {:?}", map);

    let keyid = map.get("keyid").map(|id| id.to_string());
    let keypath = map.get("keypath").map(|p| p.to_string());
    let encrypter = map.get("encrypter").unwrap_or(&"kbs").to_string();

    Ok(InputParams {
        keyid,
        keypath,
        encrypter,
    })
}

/// The input params vector should only have one element.
/// The format of the element is in the following format:
/// ```plaintext
/// <key1>=<value1>::<key2>=<value2>::...
/// ```
///
/// That is, a set of key-value pairs separated by double colons.
/// Now the supported key-value pairs are
/// | Key       |             Value                    | Usage                                                                                            |
/// |-----------|--------------------------------------|--------------------------------------------------------------------------------------------------|
/// | keyid     | a KBS Resource URI, s.t. `kbs://..`  | Specify the KEK of this image. keyid field will be included in AnnotationPacket                  |
/// | keypath   | path to the KEK, e.g. `/home/key`    | Specify the KEK to encrypted the image in local filesystem                                       |
/// | encrypter | KMS plugin name, e.g. `kbs`, `aliyun`| Specify the KMS plugin to encrypt the image                                                      |
pub async fn enc_optsdata_gen_anno(optsdata: &[u8], params: Vec<String>) -> Result<String> {
    let input_params = parse_input_params(&params[0])?;
    let mut encrypter = init_image_encrypter(&input_params.encrypter).await?;

    info!("using {} to encrypt image...", input_params.encrypter);

    let kek = match input_params.keypath {
        Some(path) => Some(tokio::fs::read(path).await?),
        None => None,
    };

    let annotation_packet = encrypter
        .encrypt_lek(optsdata, input_params.keyid, kek)
        .await?;

    debug!("encryption succeed. AnnotationPacket: {annotation_packet:?}");
    serde_json::to_string(&annotation_packet)
        .map_err(|_| anyhow!("Serialize annotation_packet failed"))
}
