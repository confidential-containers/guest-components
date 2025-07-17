// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use jwt_simple::prelude::Ed25519KeyPair;
use log::{debug, info};
use rand::TryRngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::fs;

use self::{crypto::Algorithm, kbs::register_kek};

mod crypto;
mod kbs;

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
    sample: bool,

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
    algorithm: Algorithm,
}

const HARD_CODED_KEYID: &str = "kbs:///default/test-key/1";

/// When a KEK is randomly generated, a new kid will be generated
/// with this prefix.
const DEFAULT_KEY_REPO_PATH: &str = "/default/image-kek";

const KBS_RESOURCE_URL_PREFIX: &str = "kbs://";

fn parse_input_params(input: &str) -> Result<InputParams> {
    let map: HashMap<&str, &str> = input
        .split("::")
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|field| field.split_once('='))
        .collect();
    debug!("Get new request: {map:?}");
    let sample = map
        .get("sample")
        .map(|sa| sa.parse::<bool>().unwrap_or(false))
        .unwrap_or(false);
    let keyid = map.get("keyid").map(|id| id.to_string());
    let keypath = map.get("keypath").map(|p| p.to_string());
    let algorithm = map
        .get("keypath")
        .map(|alg| (*alg).try_into().unwrap_or_default())
        .unwrap_or_default();
    Ok(InputParams {
        sample,
        keyid,
        keypath,
        algorithm,
    })
}

/// This function will generate (key, iv, keyid) for given `InputParams`
async fn generate_key_parameters(input_params: &InputParams) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let sample_flag = input_params.sample;
    match sample_flag {
        // sample keyprovider will use hard coded key and iv
        true => {
            info!("Use sample keyprovider (HARDCODED KEY and IV)");
            Ok((
                crypto::HARDCODED_KEY.to_vec(),
                [0; 12].to_vec(),
                HARD_CODED_KEYID.into(),
            ))
        }
        // use input key and randomly generated iv
        false => match &input_params.keypath {
            Some(kpath) => {
                debug!("use given key from: {kpath}");
                let key = fs::read(kpath).await.context("read Key file failed")?;
                let mut iv = [0; 12];
                rand::rngs::OsRng.try_fill_bytes(&mut iv)?;
                let kid = match &input_params.keyid {
                    Some(kid) => kid.to_string(),
                    None => {
                        debug!("no kid input, generate a random kid");
                        let tag = uuid::Uuid::new_v4().to_string();
                        format!("{DEFAULT_KEY_REPO_PATH}/{tag}")
                    }
                };

                Ok((key.to_vec(), iv.to_vec(), kid))
            }
            None => {
                debug!("no key input, generate a random key");

                let mut iv = [0; 12];
                rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

                let mut key = [0; 32];
                rand::rngs::OsRng.try_fill_bytes(&mut key)?;

                let kid = match &input_params.keyid {
                    Some(kid) => kid.to_string(),
                    None => {
                        debug!("no kid input, generate a random kid");
                        let tag = uuid::Uuid::new_v4().to_string();
                        format!("{DEFAULT_KEY_REPO_PATH}/{tag}")
                    }
                };
                Ok((key.to_vec(), iv.to_vec(), kid))
            }
        },
    }
}

/// Normalize the given keyid into (kbs addr, key path), s.t.
/// converting `kbs://...` or `../..` to `(<kbs-addr>, <repository>/<type>/<tag>)`.
fn normalize_path(keyid: &str) -> Result<(String, String)> {
    debug!("normalize key id {keyid}");
    let path = keyid.strip_prefix(KBS_RESOURCE_URL_PREFIX).unwrap_or(keyid);
    let values: Vec<&str> = path.split('/').collect();
    if values.len() == 4 {
        Ok((
            values[0].to_string(),
            format!("{}/{}/{}", values[1], values[2], values[3]),
        ))
    } else {
        bail!(
            "Resource path {keyid} must follow one of the following formats:
                'kbs:///<repository>/<type>/<tag>'
                'kbs://<kbs-addr>/<repository>/<type>/<tag>'
                '<kbs-addr>/<repository>/<type>/<tag>'
                '/<repository>/<type>/<tag>'
            "
        )
    }
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
pub async fn enc_optsdata_gen_anno(
    kbs_parameter: (&Option<Url>, &Option<Ed25519KeyPair>),
    optsdata: &[u8],
    params: Vec<String>,
) -> Result<String> {
    let input_params = parse_input_params(&params[0])?;
    let (key, iv, kid) = generate_key_parameters(&input_params)
        .await
        .context("generating key params")?;

    let (kbs_addr, k_path) = normalize_path(&kid)?;

    let algorithm = input_params.algorithm;
    let encrypt_optsdata = crypto::encrypt(optsdata, &key, &iv, &algorithm)
        .map_err(|e| anyhow!("Encrypt failed: {:?}", e))?;

    if let (Some(addr), Some(private_key)) = kbs_parameter {
        if !input_params.sample {
            // We do not register KEK for sample kbc
            register_kek(private_key, addr, key, &k_path)
                .await
                .context("register KEK failed")?;
            info!("register KEK succeeded.");
        }
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let annotation = AnnotationPacket {
        kid: format!("{KBS_RESOURCE_URL_PREFIX}{kbs_addr}/{k_path}"),
        wrapped_data: engine.encode(encrypt_optsdata),
        iv: engine.encode(iv),
        wrap_type: algorithm.to_string(),
    };

    serde_json::to_string(&annotation).map_err(|_| anyhow!("Serialize annotation failed"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    #[case("kbs://a/b/c/d", ("a", "b/c/d"))]
    #[case("kbs:///b/c/d", ("", "b/c/d"))]
    #[case("a/b/c/d", ("a", "b/c/d"))]
    #[case("/b/c/d", ("", "b/c/d"))]
    fn test_normalize_keypath(#[case] input: &str, #[case] expected: (&str, &str)) {
        let res = crate::enc_mods::normalize_path(input).expect("normalize failed");
        assert_eq!(res.0, expected.0);
        assert_eq!(res.1, expected.1);
    }
}
