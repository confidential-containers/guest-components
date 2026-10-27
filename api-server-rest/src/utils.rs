// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;

/// Split `token_type` from the other query parameters.
///
/// Every query field except `token_type` is a token parameter. ASR does not
/// decide which keys a token type accepts.
pub fn token_query_params(
    query: &HashMap<String, String>,
) -> Result<(String, HashMap<String, String>)> {
    let Some(token_type) = query.get("token_type").cloned() else {
        bail!("missing token_type");
    };
    let mut params = query.clone();
    params.remove("token_type");
    Ok((token_type, params))
}

/// Parse a `POST /aa/token` body as a JSON object of strings.
///
/// Values must be strings. Nested JSON, such as `"runtime_data": { ... }`, is
/// rejected. An empty body contributes no parameters.
pub fn token_body_params(body: &[u8]) -> Result<HashMap<String, String>> {
    if body.is_empty() {
        return Ok(HashMap::new());
    }
    serde_json::from_slice(body).context("token parameter body must be a JSON object of strings")
}

/// Parse `runtime_data` from the evidence query string.
///
/// When `encoding` is `base64`, `runtime_data` is decoded as URL-safe base64 (no padding).
/// Otherwise the raw UTF-8 bytes of the query value are used (legacy behavior).
pub fn decode_runtime_data(runtime_data: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    match encoding {
        None => Ok(runtime_data.as_bytes().to_vec()),
        Some("base64") => URL_SAFE_NO_PAD
            .decode(runtime_data)
            .context("invalid base64 URL-safe runtime_data"),
        Some(other) => Err(anyhow!("unsupported runtime_data encoding: {other}")),
    }
}

pub fn split_nth_slash(url: &str, n: usize) -> Option<(&str, &str)> {
    let mut split_pos = None;
    let mut splits = url.match_indices('/');

    for _ in 0..n {
        split_pos = splits.next();
    }

    split_pos.map(|(idx, pat)| url.split_at(idx + pat.len() - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("hello", None, true, Some(b"hello".as_slice()))]
    #[case("cmVwb3J0", Some("base64"), true, Some(b"report".as_slice()))]
    #[case("data", Some("hex"), false, None)]
    #[case("!!!", Some("base64"), false, None)]
    fn test_decode_runtime_data(
        #[case] runtime_data: &str,
        #[case] encoding: Option<&str>,
        #[case] expect_ok: bool,
        #[case] expected: Option<&[u8]>,
    ) {
        let result = decode_runtime_data(runtime_data, encoding);
        if expect_ok {
            assert_eq!(result.unwrap(), expected.unwrap());
        } else {
            assert!(result.is_err());
        }
    }

    fn query(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn token_query_params_keeps_fields_other_than_token_type() {
        let (token_type, params) =
            token_query_params(&query(&[("token_type", "coco_as"), ("nonce", "abc")])).unwrap();
        assert_eq!(token_type, "coco_as");
        assert_eq!(params.get("nonce").map(String::as_str), Some("abc"));
        assert!(token_query_params(&query(&[])).is_err());
    }

    #[rstest]
    #[case(br#"{"runtime_data":"{\"request\":\"1\"}"}"# as &[u8], true, Some(r#"{"request":"1"}"#))]
    #[case(br#"not-json"# as &[u8], false, None)]
    #[case(br#"["runtime_data"]"# as &[u8], false, None)]
    #[case(br#"{"runtime_data":{"request":"1"}}"# as &[u8], false, None)]
    #[case(br#"{"runtime_data":null}"# as &[u8], false, None)]
    #[case(br#"{"runtime_data":1}"# as &[u8], false, None)]
    fn token_body_params(
        #[case] body: &[u8],
        #[case] expect_ok: bool,
        #[case] runtime_data: Option<&str>,
    ) {
        let result = super::token_body_params(body);
        if expect_ok {
            assert_eq!(
                result
                    .expect("body")
                    .get("runtime_data")
                    .map(String::as_str),
                runtime_data
            );
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_split_nth_slash() {
        let url_path = "/cdh/resource/default/";
        assert_eq!(split_nth_slash(url_path, 0), None);
        assert_eq!(
            split_nth_slash(url_path, 1),
            Some(("", "/cdh/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 2),
            Some(("/cdh", "/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 3),
            Some(("/cdh/resource", "/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 4),
            Some(("/cdh/resource/default", "/"))
        );
        assert_eq!(split_nth_slash(url_path, 5), None);
    }
}
