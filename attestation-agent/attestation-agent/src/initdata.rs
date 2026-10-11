// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::Result;

use kbs_types::HashAlgorithm;
use serde::Deserialize;

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Deserialize)]
pub struct Initdata {
    pub version: String,
    pub algorithm: HashAlgorithm,
    pub data: HashMap<String, String>,
}

impl Initdata {
    /// Create a new Initdata instance from a TOML string.
    pub fn parse_and_get_digest(toml: &str) -> Result<(Self, Vec<u8>)> {
        let initdata: Initdata = toml::de::from_str(toml)?;
        let digest = initdata.algorithm.digest(toml.as_bytes());
        Ok((initdata, digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // One case per supported algorithm; each case checks parsing, digest
    // length, determinism, and data extraction in a single pass.
    #[rstest]
    #[case(
        "sha256",
        concat!(
            "version = \"0.1.0\"\n",
            "algorithm = \"sha256\"\n",
            "\n[data]\n",
            "key1 = \"value1\"\n",
            "key2 = \"value2\"\n",
        ),
        32,  // SHA-256 produces 32 bytes
        Some(("key1", "value1"))
    )]
    #[case(
        "sha384",
        concat!(
            "version = \"0.1.0\"\n",
            "algorithm = \"sha384\"\n",
            "\n[data]\n",
            "foo = \"bar\"\n",
        ),
        48,  // SHA-384 produces 48 bytes
        None
    )]
    fn test_parse_and_get_digest(
        #[case] _label: &str,
        #[case] toml: &str,
        #[case] expected_digest_len: usize,
        #[case] expected_data_entry: Option<(&str, &str)>,
    ) {
        let (initdata, digest) = Initdata::parse_and_get_digest(toml)
            .expect("parse_and_get_digest failed");

        assert_eq!(initdata.version, "0.1.0");
        assert_eq!(digest.len(), expected_digest_len);

        // digest is deterministic: a second call on the same input matches
        let (_, digest2) = Initdata::parse_and_get_digest(toml).unwrap();
        assert_eq!(digest, digest2);

        if let Some((key, val)) = expected_data_entry {
            assert_eq!(initdata.data.get(key).map(String::as_str), Some(val));
        }
    }

    #[rstest]
    #[case("this is not valid toml :::")]
    #[case("version = \"0.1.0\"\n[data]\nkey = \"val\"\n")]  // missing algorithm
    #[case("version = \"0.1.0\"\nalgorithm = \"md5\"\n[data]\n")]  // unsupported algorithm
    fn test_parse_and_get_digest_invalid(#[case] toml: &str) {
        assert!(Initdata::parse_and_get_digest(toml).is_err());
    }
}
