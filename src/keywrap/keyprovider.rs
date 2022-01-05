// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use crate::config::{Command, DecryptConfig, EncryptConfig, KeyProviderAttrs};
use crate::keywrap::KeyWrapper;
use crate::utils;
use crate::utils::keyprovider as keyproviderpb;
use crate::utils::CommandExecuter;
use anyhow::{anyhow, Result};
use core::fmt;
use core::fmt::Debug;
use core::option::Option;
use serde::Serialize;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use tokio;
use tokio::runtime::Runtime;
use tonic;
use tonic::codegen::http::Uri;

impl Debug for dyn CommandExecuter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CommandExecuter")
    }
}

/// A KeyProvider keywrapper
#[derive(Debug)]
pub struct KeyProviderKeyWrapper {
    pub provider: String,
    pub attrs: KeyProviderAttrs,
    pub runner: Option<Box<dyn CommandExecuter>>,
}

#[derive(Debug)]
enum OpKey {
    Wrap,
    Unwrap,
}

impl fmt::Display for OpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            OpKey::Wrap => write!(f, "keywrap"),
            OpKey::Unwrap => write!(f, "keyunwrap"),
        }
    }
}

/// KeyProviderKeyWrapProtocolInput defines the input to the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyProviderKeyWrapProtocolInput {
    /// op is either "keywrap" or "keyunwrap"
    op: String,
    /// keywrapparams encodes the arguments to key wrap if operation is set to wrap
    #[serde(rename = "keywrapparams")]
    key_wrap_params: KeyWrapParams,
    /// keyunwrapparams encodes the arguments to key unwrap if operation is set to unwrap
    #[serde(rename = "keyunwrapparams")]
    key_unwrap_params: KeyUnwrapParams,
}

/// KeyProviderKeyWrapProtocolOutput defines the output of the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Default)]
pub struct KeyProviderKeyWrapProtocolOutput {
    /// keywrapresults encodes the results to key wrap if operation is to keywrap
    #[serde(rename = "keywrapresults", skip_serializing_if = "Option::is_none")]
    key_wrap_results: Option<KeyWrapResults>,
    /// keyunwrapresults encodes the result to key unwrap if operation is to keyunwrap
    #[serde(rename = "keyunwrapresults", skip_serializing_if = "Option::is_none")]
    key_unwrap_results: Option<KeyUnwrapResults>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyWrapParams {
    pub ec: Option<EncryptConfig>,
    #[serde(rename = "optsdata")]
    opts_data: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyUnwrapParams {
    pub dc: Option<DecryptConfig>,
    annotation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyUnwrapResults {
    #[serde(rename = "optsdata")]
    opts_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyWrapResults {
    annotation: Vec<u8>,
}

/// new_key_wrapper returns a KeyProviderKeyWrapper
pub fn new_key_wrapper(
    provider: String,
    mut attrs: KeyProviderAttrs,
    runner: Option<Box<dyn utils::CommandExecuter>>,
) -> KeyProviderKeyWrapper {
    if let Some(grpc) = &attrs.grpc {
        if !grpc.starts_with("http://") && !grpc.starts_with("tcp://") {
            attrs.grpc = Some(format!("http://{}", grpc));
        }
    }

    KeyProviderKeyWrapper {
        provider,
        attrs,
        runner,
    }
}

impl KeyProviderKeyWrapProtocolOutput {
    async fn from_grpc(input: Vec<u8>, conn: &str, operation: OpKey) -> Result<Self> {
        let uri = conn.parse::<Uri>().unwrap();
        // create a channel ie connection to server
        let channel = tonic::transport::Channel::builder(uri)
            .connect()
            .await
            .map_err(|e| anyhow!("Error while creating channel: {:?}", e))?;

        let mut client =
            keyproviderpb::key_provider_service_client::KeyProviderServiceClient::new(channel);
        let request = tonic::Request::new(keyproviderpb::KeyProviderKeyWrapProtocolInput {
            key_provider_key_wrap_protocol_input: input,
        });
        let grpc_output = match operation {
            OpKey::Wrap => client.wrap_key(request).await.map_err(|_| {
                anyhow!(
                    "Error from grpc request method on {:?} operation",
                    OpKey::Wrap.to_string()
                )
            })?,

            OpKey::Unwrap => client.un_wrap_key(request).await.map_err(|_| {
                anyhow!(
                    "Error from grpc request method on {:?} operation",
                    OpKey::Unwrap.to_string()
                )
            })?,
        };

        let protocol_output = serde_json::from_slice(
            &grpc_output
                .into_inner()
                .key_provider_key_wrap_protocol_output,
        )
        .map_err(|_| {
            anyhow!(
                "Error while deserializing grpc output on {:?} operation",
                OpKey::Unwrap.to_string()
            )
        })?;
        Ok(protocol_output)
    }

    fn from_command(
        input: Vec<u8>,
        cmd: &Option<Command>,
        runner: &dyn utils::CommandExecuter,
    ) -> Result<Self> {
        let command = cmd.as_ref().unwrap();
        let cmd_name = command.path.to_string();
        let mut args = &vec![];
        if command.args.as_ref().is_some() {
            args = command.args.as_ref().unwrap();
        }
        let resp_bytes: Vec<u8> = runner
            .exec(cmd_name, args, input)
            .map_err(|_| anyhow!("Error from command executer"))?;
        let protocol_output: KeyProviderKeyWrapProtocolOutput = serde_json::from_slice(&resp_bytes)
            .map_err(|_| anyhow!("Error while deserializing command executer output"))?;

        Ok(protocol_output)
    }
}

impl KeyWrapper for KeyProviderKeyWrapper {
    /// WrapKeys calls appropriate binary-executable or grpc/ttrpc server for wrapping the session key for recipients and gets encrypted optsData, which
    /// describe the symmetric key used for encrypting the layer
    fn wrap_keys(&self, enc_config: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        let opts_data_str = String::from_utf8(opts_data.to_vec())
            .map_err(|_| anyhow!("Error while converting bytes to string"))?;
        let key_wrap_params = KeyWrapParams {
            ec: Some(enc_config.clone()),
            opts_data: Some(opts_data_str),
        };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OpKey::Wrap.to_string(),
            key_wrap_params,
            key_unwrap_params: KeyUnwrapParams::default(),
        };
        let serialized_input = serde_json::to_vec(&input).map_err(|_| {
            anyhow!(
                "Error while serializing key provider input parameters on {:?} operation",
                OpKey::Wrap.to_string()
            )
        })?;

        if enc_config.param.contains_key(&self.provider.to_string()) {
            let protocol_output = if self.attrs.cmd.as_ref().is_some() {
                KeyProviderKeyWrapProtocolOutput::from_command(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()).map_err(|e| anyhow!("Error while key provider {:?} operation, from binary executable provider, error: {:?}", OpKey::Wrap.to_string(), e))?
            } else if self.attrs.grpc.as_ref().is_some() {
                let rt =
                    Runtime::new()
                        .unwrap()
                        .block_on(KeyProviderKeyWrapProtocolOutput::from_grpc(
                            serialized_input,
                            self.attrs.grpc.as_ref().unwrap(),
                            OpKey::Wrap,
                        ));
                rt.map_err(|e| {
                    anyhow!(
                        "Error while key provider {:?} operation, from grpc provider, error: {:?}",
                        OpKey::Wrap.to_string(),
                        e
                    )
                })?
            } else {
                KeyProviderKeyWrapProtocolOutput::default()
            };
            Ok(protocol_output.key_wrap_results.unwrap().annotation)
        } else {
            return Err(anyhow!(
                "Error while key provider {:?} operation, unsupported protocol",
                OpKey::Wrap.to_string()
            ));
        }
    }

    /// UnwrapKey calls appropriate binary-executable or grpc/ttrpc server for unwrapping the session key based on the protocol given in annotation for recipients and gets decrypted optsData,
    /// which describe the symmetric key used for decrypting the layer
    fn unwrap_keys(&self, dc_config: &DecryptConfig, json_string: &[u8]) -> Result<Vec<u8>> {
        let annotation_str = String::from_utf8(json_string.to_vec())
            .map_err(|_| anyhow!("Error while converting bytes to string"))?;
        let key_unwrap_params = KeyUnwrapParams {
            dc: Some(dc_config.clone()),
            annotation: Some(base64::encode(annotation_str)),
        };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OpKey::Unwrap.to_string(),
            key_wrap_params: KeyWrapParams::default(),
            key_unwrap_params,
        };
        let serialized_input = serde_json::to_vec(&input).map_err(|_| {
            anyhow!(
                "Error while serializing key provider input parameters on {:?} operation",
                OpKey::Unwrap.to_string()
            )
        })?;

        let protocol_output = if self.attrs.cmd.as_ref().is_some() {
            KeyProviderKeyWrapProtocolOutput::from_command(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()).map_err(|e| anyhow!("Error while key provider {:?} operation, from binary executable provider, error: {:?}", OpKey::Unwrap.to_string(), e))?
        } else if self.attrs.grpc.as_ref().is_some() {
            let rt = Runtime::new()
                .unwrap()
                .block_on(KeyProviderKeyWrapProtocolOutput::from_grpc(
                    serialized_input,
                    self.attrs.grpc.as_ref().unwrap(),
                    OpKey::Unwrap,
                ));
            rt.map_err(|e| anyhow!("Error while key provider {:?} operation, from grpc provider error, error: {:?}", OpKey::Unwrap.to_string(), e))?
        } else {
            KeyProviderKeyWrapProtocolOutput::default()
        };

        Ok(protocol_output
            .key_unwrap_results
            .unwrap_or_default()
            .opts_data)
    }

    fn annotation_id(&self) -> String {
        format!(
            "{}{}",
            "org.opencontainers.image.enc.keys.provider.", self.provider
        )
    }

    fn no_possible_keys(&self, _dc_param: &HashMap<String, Vec<Vec<u8>>, RandomState>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::config;
    use crate::config::{DecryptConfig, EncryptConfig};
    use crate::keywrap::keyprovider::{
        new_key_wrapper, KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput,
        KeyUnwrapResults, KeyWrapResults,
    };
    use crate::keywrap::{keyprovider, KeyWrapper};
    use crate::utils::keyprovider::key_provider_service_server::KeyProviderService;
    use crate::utils::keyprovider::key_provider_service_server::KeyProviderServiceServer;
    use crate::utils::keyprovider::{
        KeyProviderKeyWrapProtocolInput as grpc_input,
        KeyProviderKeyWrapProtocolOutput as grpc_output,
    };
    use crate::utils::CommandExecuter;
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use anyhow::{anyhow, Result};
    use std::collections::HashMap;
    use std::io::{Error, ErrorKind};
    use std::net::SocketAddr;
    use std::thread::sleep;
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use tokio::sync::mpsc;
    use tonic;
    use tonic::{transport::Server, Request};

    ///Test runner which mocks binary executable for key wrapping and unwrapping
    #[derive(Clone, Copy)]
    pub struct TestRunner {}

    static mut ENC_KEY: &[u8; 32] = b"passphrasewhichneedstobe32bytes!";
    static mut DEC_KEY: &[u8; 32] = b"passphrasewhichneedstobe32bytes!";

    ///Mock annotation packet, which goes into container image manifest
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AnnotationPacket {
        pub key_url: String,
        pub wrapped_key: Vec<u8>,
        pub wrap_type: String,
    }

    ///grpc server with mock api implementation for serving the clients with mock WrapKey and Unwrapkey grpc method implementations
    #[derive(Default)]
    struct TestServer {}

    pub fn encrypt_key(plain_text: &[u8], encrypting_key: &[u8; 32]) -> Result<Vec<u8>> {
        let encrypting_key = Key::from_slice(encrypting_key);
        let cipher = Aes256Gcm::new(encrypting_key);
        let nonce = Nonce::from_slice(b"unique nonce");

        cipher
            .encrypt(nonce, plain_text.as_ref())
            .map_err(|_| anyhow!("encryption failure"))
    }

    pub fn decrypt_key(cipher_text: &[u8], decrypting_key: &[u8; 32]) -> Result<Vec<u8>> {
        let decrypting_key = Key::from_slice(decrypting_key);
        let cipher = Aes256Gcm::new(decrypting_key);
        let nonce = Nonce::from_slice(b"unique nonce");

        cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|_| anyhow!("decryption failure"))
    }

    #[tonic::async_trait]
    impl KeyProviderService for TestServer {
        async fn wrap_key(
            &self,
            request: Request<grpc_input>,
        ) -> core::result::Result<tonic::Response<grpc_output>, tonic::Status> {
            let key_wrap_input: keyprovider::KeyProviderKeyWrapProtocolInput =
                serde_json::from_slice(&request.into_inner().key_provider_key_wrap_protocol_input)
                    .unwrap();
            let plain_optsdata = key_wrap_input.key_wrap_params.opts_data.unwrap();
            if let Ok(wrapped_key_result) =
                encrypt_key(&base64::decode(plain_optsdata).unwrap(), unsafe { ENC_KEY })
            {
                let ap = AnnotationPacket {
                    key_url: "https://key-provider/key-uuid".to_string(),
                    wrapped_key: wrapped_key_result,
                    wrap_type: "AES".to_string(),
                };
                let serialized_ap = serde_json::to_vec(&ap).unwrap();
                let key_wrap_output = KeyProviderKeyWrapProtocolOutput {
                    key_wrap_results: Some(KeyWrapResults {
                        annotation: serialized_ap,
                    }),
                    key_unwrap_results: None,
                };
                let serialized_key_wrap_output = serde_json::to_vec(&key_wrap_output).unwrap();

                Ok(tonic::Response::new(grpc_output {
                    key_provider_key_wrap_protocol_output: serialized_key_wrap_output,
                }))
            } else {
                Err(tonic::Status::unknown("Error while encrypting key"))
            }
        }

        async fn un_wrap_key(
            &self,
            request: Request<grpc_input>,
        ) -> core::result::Result<tonic::Response<grpc_output>, tonic::Status> {
            let key_wrap_input: keyprovider::KeyProviderKeyWrapProtocolInput =
                serde_json::from_slice(&request.into_inner().key_provider_key_wrap_protocol_input)
                    .unwrap();
            let base64_annotation = key_wrap_input.key_unwrap_params.annotation.unwrap();
            let vec_annotation = base64::decode(base64_annotation).unwrap();
            let str_annotation: &str = std::str::from_utf8(&vec_annotation).unwrap();
            let annotation_packet: AnnotationPacket = serde_json::from_str(str_annotation).unwrap();
            let wrapped_key = annotation_packet.wrapped_key;
            if let Ok(unwrapped_key_result) = decrypt_key(&wrapped_key, unsafe { DEC_KEY }) {
                let key_wrap_output = KeyProviderKeyWrapProtocolOutput {
                    key_wrap_results: None,
                    key_unwrap_results: Some(KeyUnwrapResults {
                        opts_data: unwrapped_key_result,
                    }),
                };
                let serialized_key_wrap_output = serde_json::to_vec(&key_wrap_output).unwrap();
                Ok(tonic::Response::new(grpc_output {
                    key_provider_key_wrap_protocol_output: serialized_key_wrap_output,
                }))
            } else {
                Err(tonic::Status::unknown("Error while decrypting key"))
            }
        }
    }

    impl CommandExecuter for TestRunner {
        /// Mock CommandExecuter for executing a linux command line command and return the output of the command with an error if it exists.
        fn exec(
            &self,
            cmd: String,
            _args: &[std::string::String],
            input: Vec<u8>,
        ) -> Result<Vec<u8>> {
            let mut key_wrap_output = KeyProviderKeyWrapProtocolOutput::default();
            if cmd == "/usr/lib/keyprovider-wrapkey" {
                let key_wrap_input: KeyProviderKeyWrapProtocolInput =
                    serde_json::from_slice(input.as_ref()).unwrap();
                let plain_optsdata = key_wrap_input.key_wrap_params.opts_data.unwrap();
                let wrapped_key =
                    encrypt_key(&base64::decode(plain_optsdata).unwrap(), unsafe { ENC_KEY })
                        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
                let ap = AnnotationPacket {
                    key_url: "https://key-provider/key-uuid".to_string(),
                    wrapped_key,
                    wrap_type: "AES".to_string(),
                };
                let serialized_ap = serde_json::to_vec(&ap).unwrap();
                key_wrap_output = KeyProviderKeyWrapProtocolOutput {
                    key_wrap_results: Some(KeyWrapResults {
                        annotation: serialized_ap,
                    }),
                    key_unwrap_results: None,
                };
            } else if cmd == "/usr/lib/keyprovider-unwrapkey" {
                let key_wrap_input: KeyProviderKeyWrapProtocolInput =
                    serde_json::from_slice(input.as_ref()).unwrap();
                let base64_annotation = key_wrap_input.key_unwrap_params.annotation.unwrap();
                let vec_annotation = base64::decode(base64_annotation).unwrap();
                let str_annotation: &str = std::str::from_utf8(&vec_annotation).unwrap();
                let annotation_packet: AnnotationPacket =
                    serde_json::from_str(str_annotation).unwrap();
                let wrapped_key = annotation_packet.wrapped_key;
                let unwrapped_key = decrypt_key(&wrapped_key, unsafe { DEC_KEY })
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
                key_wrap_output = KeyProviderKeyWrapProtocolOutput {
                    key_wrap_results: None,
                    key_unwrap_results: Some(KeyUnwrapResults {
                        opts_data: unwrapped_key,
                    }),
                };
            }
            let serialized_keywrap_output = serde_json::to_vec(&key_wrap_output).unwrap();

            Ok(serialized_keywrap_output)
        }
    }

    #[test]
    #[ignore]
    fn test_key_provider_command_success() {
        let test_runner = TestRunner {};
        let mut provider = HashMap::new();
        let mut dc_params = vec![];
        let mut attrs = config::KeyProviderAttrs {
            cmd: Some(config::Command {
                path: "/usr/lib/keyprovider-wrapkey".to_string(),
                args: None,
            }),
            grpc: None,
        };
        provider.insert(String::from("provider"), attrs.clone());
        let mut keyprovider_key_wrapper = new_key_wrapper(
            "keyprovider".to_string(),
            attrs.clone(),
            Some(Box::new(test_runner)),
        );

        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        // Prepare for mock encryption config
        let opts_data = b"symmetric_key";
        let b64_opts_data = base64::encode(opts_data).into_bytes();
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper
            .wrap_keys(&ec, &b64_opts_data)
            .is_ok());

        // Perform key-provider wrap-key operation
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, &b64_opts_data);

        // Create keyprovider-key-wrapper
        attrs = config::KeyProviderAttrs {
            cmd: Some(config::Command {
                path: "/usr/lib/keyprovider-unwrapkey".to_string(),
                args: None,
            }),
            grpc: None,
        };
        provider.insert(String::from("provider"), attrs.clone());
        keyprovider_key_wrapper = new_key_wrapper(
            "keyprovider".to_string(),
            attrs,
            Some(Box::new(test_runner)),
        );
        // Prepare for mock encryption config
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        let json_string = key_wrap_output_result.unwrap();
        // Perform key-provider wrap-key operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, &json_string);
        let unwrapped_key = key_wrap_output_result.unwrap();
        assert_eq!(opts_data.to_vec(), unwrapped_key);
    }

    #[test]
    fn test_command_executer_wrap_key_fail() {
        let test_runner = TestRunner {};
        let mut ec_params = vec![];
        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs {
            cmd: Some(config::Command {
                path: "/usr/lib/keyprovider-wrapkey".to_string(),
                args: None,
            }),
            grpc: None,
        };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper(
            "keyprovider".to_string(),
            attrs,
            Some(Box::new(test_runner)),
        );

        let b64_opts_data = base64::encode(b"symmetric_key").into_bytes();
        let mut ec = EncryptConfig::default();
        ec_params.push("keyprovider1".to_string().into_bytes());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper
            .wrap_keys(&ec, &b64_opts_data)
            .is_err());
    }

    #[test]
    fn test_command_executer_unwrap_key_fail() {
        let test_runner = TestRunner {};
        let mut dc_params = vec![];

        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs {
            cmd: Some(config::Command {
                path: "/usr/lib/keyprovider-unwrapkey".to_string(),
                args: None,
            }),
            grpc: None,
        };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper(
            "keyprovider".to_string(),
            attrs,
            Some(Box::new(test_runner)),
        );

        // Perform manual encryption
        let opts_data = b"symmetric_key";
        let wrapped_key = encrypt_key(opts_data.as_ref(), unsafe { ENC_KEY }).unwrap();
        let ap = AnnotationPacket {
            key_url: "https://key-provider/key-uuid".to_string(),
            wrapped_key,
            wrap_type: "AES".to_string(),
        };
        let serialized_ap = serde_json::to_vec(&ap).unwrap();

        // Change the decryption key so that decryption should fail
        unsafe { DEC_KEY = b"wrong_passwhichneedstobe32bytes!" };

        // Prepare for mock decryption config
        dc_params.push("keyprovider1".to_string().as_bytes().to_vec());
        let mut dc = DecryptConfig::default();
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        assert!(keyprovider_key_wrapper
            .unwrap_keys(&dc, &serialized_ap)
            .is_err());
    }

    // Function to start a mock grpc server
    fn start_grpc_server(sock_address: String) {
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let addr: SocketAddr = sock_address.parse().unwrap();
            let server = TestServer::default();
            let serve = Server::builder()
                .add_service(KeyProviderServiceServer::new(server))
                .serve(addr);

            tokio::spawn(async move {
                if let Err(e) = serve.await {
                    eprintln!("Error = {:?}", e);
                }

                tx.send(()).unwrap();
            });

            rx.recv().await;
        });
    }

    #[test]
    fn test_key_provider_grpc_tcp_success() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        start_grpc_server("127.0.0.1:8990".to_string());
        // sleep for few seconds so that grpc server bootstraps
        sleep(Duration::from_secs(1));
        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        let mut provider = HashMap::new();
        let mut dc_params = vec![];
        let attrs = config::KeyProviderAttrs {
            cmd: None,
            grpc: Some("tcp://127.0.0.1:8990".to_string()),
        };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs, None);

        // Prepare encryption config params
        let opts_data = b"symmetric_key";
        let b64_opts_data = base64::encode(opts_data).into_bytes();
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, &b64_opts_data);

        // Perform decryption-config params
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        let json_string = key_wrap_output_result.unwrap();

        // Perform unwrapkey operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, &json_string);
        let unwrapped_key = key_wrap_output_result.unwrap();
        assert_eq!(opts_data.to_vec(), unwrapped_key);
        // runtime shutdown for stopping grpc server
        rt.shutdown_background();
    }

    #[test]
    fn test_key_provider_grpc_http_success() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        start_grpc_server("127.0.0.1:8991".to_string());
        // sleep for few seconds so that grpc server bootstraps
        sleep(Duration::from_secs(1));
        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        let mut provider = HashMap::new();
        let mut dc_params = vec![];
        let attrs = config::KeyProviderAttrs {
            cmd: None,
            grpc: Some("http://127.0.0.1:8991".to_string()),
        };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs, None);

        // Prepare encryption config params
        let opts_data = b"symmetric_key";
        let b64_opts_data = base64::encode(opts_data).into_bytes();
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, &b64_opts_data);

        // Perform decryption-config params
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        let json_string = key_wrap_output_result.unwrap();

        // Perform unwrapkey operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, &json_string);
        let unwrapped_key = key_wrap_output_result.unwrap();
        assert_eq!(opts_data.to_vec(), unwrapped_key);

        // runtime shutdown for stopping grpc server
        rt.shutdown_background();
    }
}
