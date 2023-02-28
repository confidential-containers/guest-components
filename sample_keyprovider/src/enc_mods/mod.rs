// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use log::{debug, info};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use self::crypto::Algorithm;

mod crypto;
/// `AnnotationPacket` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/attestation-agent/issues/113>
#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

struct InputParams {
    /// Whether this image is encrypted by sample key provider.
    /// By default `false`.
    /// If `sample` is enabled, the `keypath` field will be ignored.
    sample: Option<bool>,

    /// Specify the KEK of this image. keyid field will be
    /// included in AnnotationPacket. For example:
    /// `kbs:///default/key/test-tag`
    keyid: Option<String>,

    /// Specify the KEK to encrypted the image in local
    /// filesystem. This key will be read from fs and then
    /// used to encrypt the image. This key's length must
    /// be 32 bytes
    keypath: Option<String>,

    /// Encryption algorithm, included in the `wrap_type`
    /// field of AnnotationPacket. Can be
    /// - `A256GCM`: aes 256 gcm (default)
    /// - `A256CTR`: aes 256 ctr
    algorithm: Option<Algorithm>,
}

const HARD_CODED_KEYID: &str = "kbs:///default/test-key/1";

fn parse_input_params(input: &str) -> Result<InputParams> {
    let map: HashMap<&str, &str> = input
        .split("::")
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|field| field.split_once('='))
        .map(|(k, v)| (k, v))
        .collect();
    debug!("Get new request: {:?}", map);
    let sample = map
        .get("sample")
        .map(|sa| sa.parse::<bool>().unwrap_or(false));
    let keyid = map.get("keyid").map(|id| id.to_string());
    let keypath = map.get("keypath").map(|p| p.to_string());
    let algorithm = map
        .get("keypath")
        .map(|alg| (*alg).try_into().unwrap_or_default());
    Ok(InputParams {
        sample,
        keyid,
        keypath,
        algorithm,
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
/// | sample    | `true` or `false`                    | Whether this image is encrypted by sample key provider. By default `false`                       |
/// | keyid     | a KBS Resource URI, s.t. `kbs://..`  | Specify the KEK of this image. keyid field will be included in AnnotationPacket                  |
/// | keypath   | path to the KEK, e.g. `/home/key`    | Specify the KEK to encrypted the image in local filesystem                                       |
/// | algorithm | `A256GCM` or `A256CTR`               | Encryption algorithm, included in the `wrap_type` field of AnnotationPacket. By default `A256GCM`|
pub fn enc_optsdata_gen_anno(optsdata: &[u8], params: Vec<String>) -> Result<String> {
    let input_params = parse_input_params(&params[0])?;
    let sample_flag = input_params.sample.unwrap_or(false);
    let (key, iv, kid) = match sample_flag {
        // sample keyprovider will use hard coded key and iv
        true => {
            info!("Use sample keyprovider (HARDCODED KEY and IV)");
            (
                crypto::HARDCODED_KEY.to_vec(),
                [0; 12],
                HARD_CODED_KEYID.into(),
            )
        }
        // use input key and randomly generated iv
        false => match input_params.keypath {
            Some(kpath) => {
                info!("Use given key : {kpath}");
                let key =
                    std::fs::read(kpath).map_err(|e| anyhow!("Read Key file failed: {}", e))?;
                let mut iv = [0; 12];
                rand::rngs::OsRng.fill_bytes(&mut iv);
                debug!("random IV generated.");
                let kid = input_params
                    .keyid
                    .ok_or_else(|| anyhow!("kid should be given when `sample` is not enabled"))?;
                (key, iv, kid)
            }
            None => bail!("`keypath` should be given when `sample` is not enabled"),
        },
    };

    let algorithm = input_params.algorithm.unwrap_or_default();
    let encrypt_optsdata = crypto::encrypt(optsdata, &key, &iv, &algorithm)
        .map_err(|e| anyhow!("Encrypt failed: {:?}", e))?;

    let annotation = AnnotationPacket {
        kid,
        wrapped_data: base64::encode(encrypt_optsdata),
        iv: base64::encode(iv),
        wrap_type: algorithm.to_string(),
    };

    serde_json::to_string(&annotation).map_err(|_| anyhow!("Serialize annotation failed"))
}
