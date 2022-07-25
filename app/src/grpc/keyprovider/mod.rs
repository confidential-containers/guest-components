// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::AttestationAPIs;
use log::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::grpc::AGENT_NAME;
use crate::ATTESTATION_AGENT;
use key_provider::key_provider_service_server::{KeyProviderService, KeyProviderServiceServer};
use key_provider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};
use message::*;

pub mod message;
pub mod key_provider {
    tonic::include_proto!("keyprovider");
}

const ERR_ANNOTATION_NOT_BASE64: &str = "annotation is not base64 encoded";
const ERR_DC_EMPTY: &str = "missing Dc value";
const ERR_KBC_KBS_NOT_BASE64: &str = "KBC/KBS pair not base64 encoded";
const ERR_KBC_KBS_NOT_FOUND: &str = "KBC/KBS pair not found";
const ERR_NO_KBC_NAME: &str = "missing KBC name";
const ERR_NO_KBS_URI: &str = "missing KBS URI";
const ERR_WRONG_DC_PARAM: &str = "Dc parameter not destined for agent";

const KBC_KBS_PAIR_SEP: &str = "::";

#[derive(Debug, Default)]
pub struct KeyProvider {}

impl TryFrom<Vec<u8>> for InputPayload {
    type Error = anyhow::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let input = KeyProviderInput::try_from(bytes)?;

        InputPayload::try_from(input)
    }
}

#[tonic::async_trait]
impl KeyProviderService for KeyProvider {
    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");

        // Deserialize and parse the gRPC input to get KBC name, KBS URI and annotation.
        let input_payload =
            InputPayload::try_from(request.into_inner().key_provider_key_wrap_protocol_input)
                .map_err(|e| {
                    error!("Parse request failed: {}", e);
                    Status::internal(format!(
                        "[ERROR:{}] Parse request failed: {}",
                        AGENT_NAME, e
                    ))
                })?;

        let attestation_agent_mutex_clone = Arc::clone(&ATTESTATION_AGENT);
        let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

        debug!("Call AA-KBC to decrypt...");

        let decrypted_optsdata = attestation_agent
            .decrypt_image_layer_annotation(
                input_payload.kbc_name,
                input_payload.kbs_uri,
                input_payload.annotation,
            )
            .await
            .map_err(|e| {
                error!("Call AA-KBC to provide key failed: {}", e);
                Status::internal(format!(
                    "[ERROR:{}] AA-KBC key provider failed: {}",
                    AGENT_NAME, e
                ))
            })?;

        debug!("Provide key successfully, get the plain PLBCO");

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };

        let output = serde_json::to_string(&output_struct)
            .unwrap()
            .as_bytes()
            .to_vec();

        debug!(
            "UnWrapKey API output: {}",
            serde_json::to_string(&output_struct).unwrap()
        );

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }

    async fn wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The WrapKey API is called...");
        debug!("WrapKey API is unimplemented!");
        Err(Status::unimplemented(format!(
            "WrapKey API of {} is unimplemented!",
            AGENT_NAME,
        )))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
struct InputPayload {
    kbc_name: String,
    // Note: URI does *not* contain a scheme prefix.
    kbs_uri: String,
    annotation: String,
}

impl TryFrom<KeyProviderInput> for InputPayload {
    type Error = anyhow::Error;

    fn try_from(kpi: KeyProviderInput) -> Result<Self, Self::Error> {
        /*
         * AA expects the received DC parameter format is:
         * "dc":{
         *     "Parameters":{
         *         "attestation-agent":["< KBC_NAME::KBS_URI (base64encode) >"]
         *     }
         * }
         */

        let annotation = get_annotation(&kpi)?;

        let (kbc_name, kbs_uri) = get_kbc_kbs_pair(&kpi)?;

        let payload = InputPayload {
            kbc_name,
            kbs_uri,
            annotation,
        };

        Ok(payload)
    }
}

fn get_annotation(kpi: &KeyProviderInput) -> Result<String> {
    let base64_annotation = kpi
        .keyunwrapparams
        .annotation
        .as_ref()
        .ok_or_else(|| anyhow!(ERR_ANNOTATION_EMPTY))?;

    let vec_annotation = base64::decode(base64_annotation)
        .map_err(|e| anyhow!("{}: {:?}", ERR_ANNOTATION_NOT_BASE64, e))?;

    let annotation: &str = str::from_utf8(&vec_annotation)?;

    if annotation.is_empty() {
        return Err(anyhow!(ERR_ANNOTATION_EMPTY));
    }

    Ok(annotation.into())
}

fn get_kbc_kbs_pair(kpi: &KeyProviderInput) -> Result<(String, String)> {
    let dc = kpi
        .keyunwrapparams
        .dc
        .as_ref()
        .ok_or_else(|| anyhow!(ERR_DC_EMPTY))?;

    if let Some(parameters_list) = dc.parameters.get(AGENT_NAME) {
        let value = if let Some(value) = parameters_list.get(0) {
            value
        } else {
            return Err(anyhow!(ERR_DC_EMPTY));
        };

        let kbc_kbs_pair_byte = base64::decode(value.clone())
            .map_err(|e| anyhow!("{}: {:?}", ERR_KBC_KBS_NOT_BASE64, e))?;

        let kbc_kbs_value = std::str::from_utf8(&kbc_kbs_pair_byte)?;

        Ok(str_to_kbc_kbs(kbc_kbs_value)?)
    } else {
        Err(anyhow!(ERR_WRONG_DC_PARAM))
    }
}

fn str_to_kbc_kbs(value: &str) -> Result<(String, String)> {
    if let Some((kbc_name, kbs_uri)) = value.split_once(KBC_KBS_PAIR_SEP) {
        if kbc_name.is_empty() {
            return Err(anyhow!(ERR_NO_KBC_NAME));
        }

        if kbs_uri.is_empty() {
            return Err(anyhow!(ERR_NO_KBS_URI));
        }

        Ok((kbc_name.to_string(), kbs_uri.to_string()))
    } else {
        Err(anyhow!(ERR_KBC_KBS_NOT_FOUND))
    }
}

pub async fn start_service(socket: SocketAddr) -> Result<()> {
    let service = KeyProvider::default();
    let _server = Server::builder()
        .add_service(KeyProviderServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::keyprovider::message::{
        ERR_INVALID_OP, ERR_MISSING_OP, ERR_UNSUPPORTED_OP, ERR_UNWRAP_PARAMS_NO_DC,
    };
    use base64::encode;

    #[test]
    fn test_get_annotation() {
        #[derive(Debug)]
        struct TestData<'a> {
            annotation: Option<&'a str>,
            result: Result<String>,
        }

        let valid_annotation = "valid annotation";
        let encoded_annotation = base64::encode(valid_annotation);

        let tests = &[
            TestData {
                annotation: None,
                result: Err(anyhow!(ERR_ANNOTATION_EMPTY)),
            },
            TestData {
                annotation: Some(""),
                result: Err(anyhow!(ERR_ANNOTATION_EMPTY)),
            },
            TestData {
                annotation: Some("."),
                result: Err(anyhow!(ERR_ANNOTATION_NOT_BASE64)),
            },
            TestData {
                annotation: Some("a"),
                result: Err(anyhow!(ERR_ANNOTATION_NOT_BASE64)),
            },
            TestData {
                annotation: Some(&encoded_annotation),
                result: Ok(valid_annotation.into()),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let annotation_string = d.annotation.map(String::from);

            let mut kpi = KeyProviderInput::default();
            kpi.keyunwrapparams.annotation = annotation_string;

            let result = get_annotation(&kpi);

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_get_kbc_kbs_pair() {
        #[derive(Debug)]
        struct TestData {
            dc: Option<Dc>,
            result: Result<(String, String)>,
        }

        let kbc_name = "kbc-name";
        let kbs_uri = "https://kbs.uri.com";

        let annotation_value = format!("{}::{}", kbc_name, kbs_uri);
        let annotation_base64 = encode(annotation_value.clone());

        let mut invalid_dc_not_base64: Dc = Dc::default();
        invalid_dc_not_base64
            .parameters
            .insert(AGENT_NAME.into(), vec![annotation_value]);

        let mut invalid_dc_wrong_name: Dc = Dc::default();
        invalid_dc_wrong_name
            .parameters
            .insert("foo bar".into(), vec![annotation_base64.clone()]);

        let mut valid_dc: Dc = Dc::default();
        valid_dc
            .parameters
            .insert(AGENT_NAME.into(), vec![annotation_base64]);

        let tests = &[
            TestData {
                dc: None,
                result: Err(anyhow!(ERR_DC_EMPTY)),
            },
            TestData {
                dc: Some(Dc::default()),
                result: Err(anyhow!(ERR_WRONG_DC_PARAM)),
            },
            TestData {
                dc: Some(invalid_dc_not_base64),
                result: Err(anyhow!(ERR_KBC_KBS_NOT_BASE64)),
            },
            TestData {
                dc: Some(invalid_dc_wrong_name),
                result: Err(anyhow!(ERR_WRONG_DC_PARAM)),
            },
            TestData {
                dc: Some(valid_dc),
                result: Ok((kbc_name.into(), kbs_uri.into())),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let mut kpi = KeyProviderInput::default();
            kpi.keyunwrapparams.dc = d.dc.clone();

            let result = get_kbc_kbs_pair(&kpi);

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_input_payload() {
        #[derive(Debug)]
        struct TestData {
            input: KeyProviderInput,
            result: Result<InputPayload>,
        }

        let mut invalid_dc = Dc::default();

        invalid_dc
            .parameters
            .insert("foo".into(), vec!["bar".into(), "baz".into()]);

        let mut invalid_dc_not_base64 = Dc::default();

        invalid_dc_not_base64
            .parameters
            .insert(AGENT_NAME.into(), vec![".".into(), "a".into()]);

        let mut valid_dc: Dc = Dc::default();

        let kbc_name = "kbc-name";
        let kbs_uri = "https://kbs.uri.com";

        let annotation_value = format!("{}::{}", kbc_name, kbs_uri);

        let annotation_base64 = encode(annotation_value);

        valid_dc
            .parameters
            .insert(AGENT_NAME.into(), vec![annotation_base64]);

        let valid_result = InputPayload {
            kbc_name: kbc_name.into(),
            kbs_uri: kbs_uri.into(),
            annotation: AGENT_NAME.into(),
        };

        let tests = &[
            TestData {
                input: KeyProviderInput::default(),
                result: Err(anyhow!(ERR_ANNOTATION_EMPTY)),
            },
            TestData {
                input: KeyProviderInput::default()
                    // Lie and pretend this is overly short base64 encoding is base64 data
                    .with_key_unwrap_params(
                        KeyUnwrapParams::default().with_base64_annotation("a".into()),
                    ),
                result: Err(anyhow!(ERR_ANNOTATION_NOT_BASE64)),
            },
            TestData {
                input: KeyProviderInput::default()
                    // Lie and pretend this is invalid byte is base64 data
                    .with_key_unwrap_params(
                        KeyUnwrapParams::default().with_base64_annotation(".".into()),
                    ),
                result: Err(anyhow!(ERR_ANNOTATION_NOT_BASE64)),
            },
            TestData {
                input: KeyProviderInput::default().with_key_unwrap_params(
                    KeyUnwrapParams::default().with_annotation(AGENT_NAME.into()),
                ),
                result: Err(anyhow!(ERR_DC_EMPTY)),
            },
            TestData {
                input: KeyProviderInput::default()
                    .with_key_unwrap_params(KeyUnwrapParams::default().with_dc(invalid_dc.clone())),
                result: Err(anyhow!(ERR_ANNOTATION_EMPTY)),
            },
            TestData {
                input: KeyProviderInput::default().with_key_unwrap_params(
                    KeyUnwrapParams::default()
                        .with_dc(invalid_dc_not_base64.clone())
                        .with_annotation(AGENT_NAME.into()),
                ),
                result: Err(anyhow!(ERR_KBC_KBS_NOT_BASE64)),
            },
            TestData {
                input: KeyProviderInput::default().with_key_unwrap_params(
                    KeyUnwrapParams::default()
                        .with_dc(invalid_dc.clone())
                        .with_annotation(AGENT_NAME.into()),
                ),
                result: Err(anyhow!(ERR_WRONG_DC_PARAM)),
            },
            TestData {
                input: KeyProviderInput::default().with_key_unwrap_params(
                    KeyUnwrapParams::default()
                        .with_dc(valid_dc.clone())
                        .with_annotation(AGENT_NAME.into()),
                ),
                result: Ok(valid_result),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let result = InputPayload::try_from(d.input.clone());

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_input_payload_try_from() {
        #[derive(Debug)]
        struct TestData {
            input: Vec<u8>,
            result: Result<InputPayload>,
        }

        let serde_eof_error = "EOF while parsing a value at line 1 column 0";

        let default_input = KeyProviderInput::default();
        let default_key_unwrap_params = KeyUnwrapParams::default();

        let kbc_name = "kbc-name";

        // Note: no URI scheme used
        let kbs_uri = "eaa_kbc::127.0.0.1:1122";

        let annotation = "annotation".to_string();

        let annotation_value = format!("{}::{}", kbc_name, kbs_uri);

        let annotation_base64 = encode(annotation_value);

        let mut valid_dc: Dc = Dc::default();

        valid_dc
            .parameters
            .insert(AGENT_NAME.into(), vec![annotation_base64]);

        let valid_key_unwrap_params = KeyUnwrapParams::default()
            .with_dc(valid_dc)
            .with_annotation(annotation.clone());

        // valid input
        let valid_key_provider_input = default_input
            .clone()
            .with_op("keyunwrap".into())
            .with_key_unwrap_params(valid_key_unwrap_params);

        // valid output
        let valid_input_payload = InputPayload {
            kbc_name: kbc_name.into(),
            kbs_uri: kbs_uri.into(),
            annotation,
        };

        let default_serialised = serde_json::to_string(&default_input).unwrap();

        let valid_serialised = serde_json::to_string(&valid_key_provider_input).unwrap();

        let invalid_op = "invalid";
        let input_invalid_op = default_input.clone().with_op(invalid_op.into());
        let invalid_op_serialised = serde_json::to_string(&input_invalid_op).unwrap();

        let unsupported_op = OP_KEY_WRAP;
        let input_unsupported_op = default_input.clone().with_op(unsupported_op.into());
        let unsupported_op_serialised = serde_json::to_string(&input_unsupported_op).unwrap();

        let supported_op = OP_KEY_UNWRAP;

        let input_op_no_unwrap_params = default_input.clone().with_op(supported_op.into());
        let op_no_unwrap_params_serialised =
            serde_json::to_string(&input_op_no_unwrap_params).unwrap();

        let input_op_with_empty_unwrap_params = default_input
            .with_op(supported_op.into())
            .with_key_unwrap_params(default_key_unwrap_params);

        let op_with_empty_unwrap_params_serialised =
            serde_json::to_string(&input_op_with_empty_unwrap_params).unwrap();

        let tests = &[
            TestData {
                input: Vec::<u8>::new(),
                result: Err(anyhow!(serde_eof_error)),
            },
            TestData {
                input: "".as_bytes().to_vec(),
                result: Err(anyhow!(serde_eof_error)),
            },
            TestData {
                input: "foo bar".as_bytes().to_vec(),
                result: Err(anyhow!("expected ident at line 1 column 2")),
            },
            TestData {
                input: default_serialised.as_bytes().to_vec(),
                result: Err(anyhow!(ERR_MISSING_OP)),
            },
            TestData {
                input: invalid_op_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}: {:?}", ERR_INVALID_OP, invalid_op)),
            },
            TestData {
                input: unsupported_op_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}: {:?}", ERR_UNSUPPORTED_OP, unsupported_op)),
            },
            TestData {
                input: op_no_unwrap_params_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}", ERR_UNWRAP_PARAMS_NO_DC)),
            },
            TestData {
                input: op_with_empty_unwrap_params_serialised.as_bytes().to_vec(),
                result: Err(anyhow!("{}", ERR_UNWRAP_PARAMS_NO_DC)),
            },
            TestData {
                input: valid_serialised.as_bytes().to_vec(),
                result: Ok(valid_input_payload),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let result = InputPayload::try_from(d.input.clone());

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }

    #[test]
    fn test_str_to_kbc_kbs() {
        #[derive(Debug)]
        struct TestData<'a> {
            value: &'a str,
            result: Result<(String, String)>,
        }

        let tests = &[
            TestData {
                value: "",
                result: Err(anyhow!(ERR_KBC_KBS_NOT_FOUND)),
            },
            TestData {
                value: ":",
                result: Err(anyhow!(ERR_KBC_KBS_NOT_FOUND)),
            },
            TestData {
                value: "::",
                result: Err(anyhow!(ERR_NO_KBC_NAME)),
            },
            TestData {
                value: ":::",
                result: Err(anyhow!(ERR_NO_KBC_NAME)),
            },
            TestData {
                value: "foo",
                result: Err(anyhow!(ERR_KBC_KBS_NOT_FOUND)),
            },
            TestData {
                value: "foo::",
                result: Err(anyhow!(ERR_NO_KBS_URI)),
            },
            TestData {
                value: "::foo",
                result: Err(anyhow!(ERR_NO_KBC_NAME)),
            },
            TestData {
                value: "foo::https://foo.bar.com/?silly=yes&colons=bar:::baz:::wibble::",
                result: Ok((
                    "foo".into(),
                    "https://foo.bar.com/?silly=yes&colons=bar:::baz:::wibble::".into(),
                )),
            },
            TestData {
                value: "eaa_kbc::127.0.0.1:1122",
                result: Ok(("eaa_kbc".into(), "127.0.0.1:1122".into())),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            // Create a string containing details of the test
            let msg = format!("test[{}]: {:?}", i, d);

            let result = str_to_kbc_kbs(d.value);

            let msg = format!("{}: result: {:?}", msg, result);

            if d.result.is_err() {
                assert!(result.is_err(), "{}", msg);

                let expected_error = format!("{:?}", d.result.as_ref().err().unwrap());
                let actual_error = format!("{:?}", result.err().unwrap());

                assert!(actual_error.starts_with(&expected_error), "{}", msg);
            } else {
                assert!(result.is_ok(), "{}", msg);

                let expected_result = d.result.as_ref().unwrap();
                let actual_result = result.unwrap();

                assert_eq!(expected_result, &actual_result, "{}", msg);
            }
        }
    }
}
