// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use crate::keywrap::KeyWrapper;
use crate::utils::keyprovider as keyproviderpb;
use tonic;
use std::collections::hash_map::RandomState;
use crate::config::{DecryptConfig, EncryptConfig, KeyProviderAttrs, Command};
use std::collections::HashMap;
use crate::{utils};
use tokio;
use crate::utils::{CommandExecuter};
use tokio::runtime::Runtime;
use core::option::Option;
use core::fmt::Debug;
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

pub const OP_KEY_WRAP: &str = "keywrap";
pub const OP_KEY_UNWRAP: &str = "keyunwrap";

/// KeyProviderKeyWrapProtocolInput defines the input to the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyProviderKeyWrapProtocolInput {
    /// op is either "keywrap" or "keyunwrap"
    #[serde(rename = "op")]
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
    #[serde(rename = "keywrapresults")]
    key_wrap_results: KeyWrapResults,
    /// keyunwrapresults encodes the result to key unwrap if operation is to keyunwrap
    #[serde(rename = "keyunwrapresults")]
    key_unwrap_results: KeyUnwrapResults,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyWrapParams {
    #[serde(rename = "ec")]
    pub ec: EncryptConfig,
    #[serde(rename = "optsdata")]
    opts_data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyUnwrapParams {
    #[serde(rename = "dc")]
    pub dc: DecryptConfig,
    #[serde(rename = "annotation")]
    annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyUnwrapResults {
    #[serde(rename = "optsdata")]
    opts_data: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct KeyWrapResults {
    #[serde(rename = "annotation")]
    annotation: Vec<u8>
}

/// new_key_wrapper returns a KeyProviderKeyWrapper
pub fn new_key_wrapper(provider: String, attrs: KeyProviderAttrs, runner: Option<Box<dyn utils::CommandExecuter>>) -> KeyProviderKeyWrapper {
    let kp = KeyProviderKeyWrapper {
        provider,
        attrs,
        runner,
    };

    kp
}

impl KeyWrapper for KeyProviderKeyWrapper {
    /// WrapKeys calls appropriate binary-executable or grpc/ttrpc server for wrapping the session key for recipients and gets encrypted optsData, which
    /// describe the symmetric key used for encrypting the layer
    fn wrap_keys(&self, enc_config: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        let mut protocol_output = KeyProviderKeyWrapProtocolOutput::default();
        let key_wrap_params = KeyWrapParams { ec: enc_config.clone(), opts_data: Vec::from(opts_data) };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OP_KEY_WRAP.to_string(),
            key_wrap_params,
            key_unwrap_params: KeyUnwrapParams::default(),
        };
        let serialized_input = match serde_json::to_vec(&input) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Error while serializing key provider input parameters on {:?} operation", OP_KEY_WRAP.to_string()))
        };

        if enc_config.param.contains_key(&self.provider.to_string()) {
            if self.attrs.cmd.as_ref().is_some() {
                protocol_output = match get_provider_command_output(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()) {
                    Ok(v) => v,
                    Err(e) => return Err(anyhow!("Error while key provider {:?} operation, from binary executable provider, error: {:?}",OP_KEY_WRAP.to_string(), e))
                };
            } else if self.attrs.grpc.as_ref().is_some() {
                let rt = Runtime::new().unwrap().block_on(get_provider_grpc_output(serialized_input, self.attrs.grpc.as_ref().unwrap(), OP_KEY_WRAP.to_string()));
                protocol_output = match rt {
                    Ok(v) => v,
                    Err(e) => return Err(anyhow!("Error while key provider {:?} operation, from grpc provider, error: {:?}",OP_KEY_WRAP.to_string(),e))
                };
            }
        } else {
            return Err(anyhow!("Error while key provider {:?} operation, unsupported protocol",OP_KEY_WRAP.to_string()))
        }

        Ok(protocol_output.key_wrap_results.annotation)
    }

    /// UnwrapKey calls appropriate binary-executable or grpc/ttrpc server for unwrapping the session key based on the protocol given in annotation for recipients and gets decrypted optsData,
    /// which describe the symmetric key used for decrypting the layer
    fn unwrap_keys(&self, dc_config: &DecryptConfig, json_string: &[u8]) -> Result<Vec<u8>> {
        let mut protocol_output = KeyProviderKeyWrapProtocolOutput::default();
        let key_unwrap_params = KeyUnwrapParams { dc: dc_config.clone(), annotation: Vec::from(json_string) };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OP_KEY_UNWRAP.to_string(),
            key_wrap_params: KeyWrapParams::default(),
            key_unwrap_params,
        };
        let serialized_input = match serde_json::to_vec(&input) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Error while serializing key provider input parameters on {:?} operation", OP_KEY_UNWRAP.to_string()))
        };

        if self.attrs.cmd.as_ref().is_some() {
            protocol_output = match get_provider_command_output(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()) {
                Ok(v) => v,
                Err(e) => return Err(anyhow!("Error while key provider {:?} operation, from binary executable provider, error: {:?}", OP_KEY_UNWRAP.to_string(), e))
            };
        } else if self.attrs.grpc.as_ref().is_some() {
            let rt = Runtime::new().unwrap().block_on(get_provider_grpc_output(serialized_input, self.attrs.grpc.as_ref().unwrap(), OP_KEY_UNWRAP.to_string()));
            protocol_output = match rt {
                Ok(v) => v,
                Err(e) => return Err(anyhow!("Error while key provider {:?} operation, from grpc provider error, error: {:?}", OP_KEY_UNWRAP.to_string(), e))
            };
        } else {
            return Err(anyhow!("Error while key provider {:?} operation, unsupported protocol",OP_KEY_UNWRAP.to_string()))
        }

        Ok(protocol_output.key_unwrap_results.opts_data)
    }


    fn annotation_id(&self) -> String {
        format!("{}{}", "org.opencontainers.image.enc.keys.provider.", self.provider)
    }

    fn no_possible_keys(&self, _dc_param: &HashMap<String, Vec<Vec<u8>>, RandomState>) -> bool {
        unimplemented!()
    }
}

async fn get_provider_grpc_output(input: Vec<u8>, conn: &str, operation: String) -> Result<KeyProviderKeyWrapProtocolOutput> {
    let mut protocol_output = KeyProviderKeyWrapProtocolOutput::default();
    let uri = conn.parse::<Uri>().unwrap();
    // create a channel ie connection to server
    let channel = match tonic::transport::Channel::builder(uri)
        .connect()
        .await {
        Ok(x) => x,
        Err(e) => return Err(anyhow!("Error while creating channel: {:?}",e))
    };
    let mut client = keyproviderpb::key_provider_service_client::KeyProviderServiceClient::new(channel);
    let request = tonic::Request::new(keyproviderpb::KeyProviderKeyWrapProtocolInput { key_provider_key_wrap_protocol_input: input });
    if operation == OP_KEY_WRAP {
        let grpc_output = match client.wrap_key(request).await {
            Ok(resp) => resp,
            Err(_) => return Err(anyhow!("Error from grpc request method on {:?} operation", OP_KEY_WRAP.to_string()))
        };
        protocol_output = match serde_json::from_slice(&grpc_output.into_inner().key_provider_key_wrap_protocol_output) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Error while deserializing grpc output on {:?} operation", OP_KEY_WRAP.to_string()))
        }
    } else if operation == OP_KEY_UNWRAP {
        let grpc_output = match client.un_wrap_key(request).await {
            Ok(resp) => resp,
            Err(_) => return Err(anyhow!("Error from grpc request method on {:?} operation", OP_KEY_UNWRAP.to_string()))
        };
        protocol_output = match serde_json::from_slice(&grpc_output.into_inner().key_provider_key_wrap_protocol_output) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Error while deserializing grpc output on {:?} operation", OP_KEY_UNWRAP.to_string()))
        };
    }
    Ok(protocol_output)
}

fn get_provider_command_output(input: Vec<u8>, cmd: &Option<Command>, runner: &Box<dyn utils::CommandExecuter>) -> Result<KeyProviderKeyWrapProtocolOutput> {
    let resp_bytes: Vec<u8>;
    if cmd.as_ref().is_some() {
        let cmd_name = cmd.as_ref().unwrap().path.to_string();
        let mut args = &vec![];
        if cmd.as_ref().unwrap().args.as_ref().is_some() {
            args = cmd.as_ref().unwrap().args.as_ref().unwrap();
        }
        resp_bytes = match runner.exec(cmd_name, args, input) {
            Ok(resp) => resp,
            Err(_) => return Err(anyhow!("Error from command executer"))
        };
        let protocol_output: KeyProviderKeyWrapProtocolOutput = match serde_json::from_slice(&resp_bytes) {
            Ok(x) => x,
            Err(_) => return Err(anyhow!("Error while deserializing command executer output"))
        };

        return Ok(protocol_output);
    }
    Err(anyhow!("No command or args specified in key provider"))
}

#[cfg(test)]
mod tests {
    use crate::utils::keyprovider::{KeyProviderKeyWrapProtocolInput as grpc_input, KeyProviderKeyWrapProtocolOutput as grpc_output};
    use crate::utils::keyprovider::{key_provider_service_server::{KeyProviderServiceServer}};
    use crate::utils::{CommandExecuter};
    use crate::keywrap::{keyprovider, KeyWrapper};
    use crate::{config};
    use std::net::SocketAddr;
    use tonic;
    use tonic::{transport::Server, Request};
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use crate::keywrap::keyprovider::{KeyProviderKeyWrapProtocolOutput, KeyWrapResults, KeyUnwrapResults, KeyProviderKeyWrapProtocolInput, new_key_wrapper};
    use crate::config::{EncryptConfig, DecryptConfig};
    use crate::utils::keyprovider::key_provider_service_server::KeyProviderService;
    use tokio::sync::mpsc;
    use tokio::runtime::Runtime;
    use std::time::Duration;
    use std::thread::sleep;
    use std::collections::HashMap;

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

    #[tonic::async_trait]
    impl KeyProviderService for TestServer {
        async fn wrap_key(
            &self,
            request: Request<grpc_input>,
        ) -> Result<tonic::Response<grpc_output>, tonic::Status> {
            let keyp: keyprovider::KeyProviderKeyWrapProtocolInput = serde_json::from_slice(&request.into_inner().key_provider_key_wrap_protocol_input).unwrap();

            let cipher = Aes256Gcm::new(Key::from_slice(unsafe { ENC_KEY }));
            let nonce = Nonce::from_slice(b"unique nonce");
            let image_layer_sym_key: &[u8] = &keyp.key_wrap_params.opts_data;
            let wrapped_key = cipher.encrypt(nonce, image_layer_sym_key).unwrap();

            let ap = AnnotationPacket {
                key_url: "https://key-provider/key-uuid".to_string(),
                wrapped_key,
                wrap_type: "AES".to_string(),
            };

            let serialized_ap = serde_json::to_vec(&ap).unwrap();

            let key_wrap_output = KeyProviderKeyWrapProtocolOutput { key_wrap_results: KeyWrapResults { annotation: serialized_ap }, key_unwrap_results: KeyUnwrapResults::default() };
            let serialized_key_wrap_output = serde_json::to_vec(&key_wrap_output).unwrap();

            Ok(tonic::Response::new(grpc_output { key_provider_key_wrap_protocol_output: serialized_key_wrap_output }))
        }

        async fn un_wrap_key(&self, request: Request<grpc_input>) -> Result<tonic::Response<grpc_output>, tonic::Status> {
            let keyp: keyprovider::KeyProviderKeyWrapProtocolInput = serde_json::from_slice(&request.into_inner().key_provider_key_wrap_protocol_input).unwrap();
            let serialized_ap: &[u8] = &keyp.key_unwrap_params.annotation;
            let ap: AnnotationPacket = serde_json::from_slice(serialized_ap).unwrap();

            let cipher = Aes256Gcm::new(Key::from_slice(unsafe { DEC_KEY }));
            let nonce = Nonce::from_slice(b"unique nonce");
            let wrapped_key = ap.wrapped_key;
            let unwrapped_key = cipher
                .decrypt(nonce, wrapped_key.as_ref())
                .expect("decryption failure!");

            let key_wrap_output = KeyProviderKeyWrapProtocolOutput { key_wrap_results: KeyWrapResults::default(), key_unwrap_results: KeyUnwrapResults { opts_data: unwrapped_key } };
            let serialized_key_wrap_output = serde_json::to_vec(&key_wrap_output).unwrap();

            Ok(tonic::Response::new(grpc_output { key_provider_key_wrap_protocol_output: serialized_key_wrap_output }))
        }
    }


    impl CommandExecuter for TestRunner {
        /// Mock CommandExecuter for executing a linux command line command and return the output of the command with an error if it exists.
        fn exec(&self, cmd: String, _args: &Vec<String>, input: Vec<u8>) -> std::io::Result<Vec<u8>> {
            let mut key_wrap_output = KeyProviderKeyWrapProtocolOutput::default();
            if cmd == "/usr/lib/keyprovider-wrapkey" {
                let key_wrap_input: KeyProviderKeyWrapProtocolInput = serde_json::from_slice(input.as_ref()).unwrap();

                let cipher = Aes256Gcm::new(Key::from_slice(unsafe { ENC_KEY }));
                let nonce = Nonce::from_slice(b"unique nonce");
                let image_layer_sym_key: &[u8] = &key_wrap_input.key_wrap_params.opts_data;
                let wrapped_key = match cipher.encrypt(nonce, image_layer_sym_key) {
                    Ok(x) => x,
                    Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "encryption failure"))
                };

                let ap = AnnotationPacket {
                    key_url: "https://key-provider/key-uuid".to_string(),
                    wrapped_key,
                    wrap_type: "AES".to_string(),
                };

                let serialized_ap = serde_json::to_vec(&ap).unwrap();
                key_wrap_output = KeyProviderKeyWrapProtocolOutput { key_wrap_results: KeyWrapResults { annotation: serialized_ap }, key_unwrap_results: KeyUnwrapResults::default() };
            } else if cmd == "/usr/lib/keyprovider-unwrapkey" {
                let key_wrap_input: KeyProviderKeyWrapProtocolInput = serde_json::from_slice(input.as_ref()).unwrap();
                let ap_bytes: &[u8] = &key_wrap_input.key_unwrap_params.annotation;
                let ap: AnnotationPacket = serde_json::from_slice(ap_bytes).unwrap();

                let cipher_text = ap.wrapped_key;
                let cipher = Aes256Gcm::new(Key::from_slice(unsafe { DEC_KEY }));
                let nonce = Nonce::from_slice(b"unique nonce");
                let image_layer_sym_key = match cipher
                    .decrypt(nonce, cipher_text.as_ref()) {
                    Ok(x) => x,
                    Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "decryption failure"))
                };

                key_wrap_output = KeyProviderKeyWrapProtocolOutput { key_wrap_results: KeyWrapResults::default(), key_unwrap_results: KeyUnwrapResults { opts_data: image_layer_sym_key } };
            }
            let serialized_keywrap_output = serde_json::to_vec(&key_wrap_output).unwrap();
            Ok(serialized_keywrap_output)
        }
    }

    #[test]
    fn test_key_provider_command_success() {
        let test_runner = TestRunner {};
        let mut provider = HashMap::new();
        let mut attrs = config::KeyProviderAttrs { cmd: Some(config::Command { path: "/usr/lib/keyprovider-wrapkey".to_string(), args: None }), grpc: None };
        provider.insert(String::from("provider"), attrs.clone());
        let mut keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), Some(Box::new(test_runner)));

        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        // Prepare for mock encryption config
        let opts_data = b"symmetric_key";
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper.wrap_keys(&ec, opts_data).is_ok());

        // Perform key-provider wrap-key operation
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, opts_data);

        // Create keyprovider-key-wrapper
        attrs = config::KeyProviderAttrs { cmd: Some(config::Command { path: "/usr/lib/keyprovider-unwrapkey".to_string(), args: None }), grpc: None };
        provider.insert(String::from("provider"), attrs.clone());
        keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), Some(Box::new(test_runner)));
        // Prepare for mock encryption config
        let mut dc_params = vec![];
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());

        // Perform key-provider wrap-key operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, key_wrap_output_result.unwrap().as_ref());
        let unwrapped_key: &[u8] = &key_wrap_output_result.unwrap();
        assert_eq!(opts_data, unwrapped_key);
    }

    #[test]
    fn test_command_executer_wrap_key_fail() {
        let test_runner = TestRunner {};
        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs { cmd: Some(config::Command { path: "/usr/lib/keyprovider-wrapkey".to_string(), args: None }), grpc: None };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), Some(Box::new(test_runner)));

        let opts_data = b"symmetric_key";
        let mut ec = EncryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider1".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper.wrap_keys(&ec, opts_data).is_err());
    }

    #[test]
    fn test_command_executer_unwrap_key_fail() {
        let test_runner = TestRunner {};
        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs { cmd: Some(config::Command { path: "/usr/lib/keyprovider-unwrapkey".to_string(), args: None }), grpc: None };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), Some(Box::new(test_runner)));

        // Prepare for mock encryption config
        let param = "keyprovider1".to_string().into_bytes();
        let mut dc_params = vec![];
        dc_params.push(param);
        let mut dc = DecryptConfig::default();
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());

        let opts_data = b"symmetric_key";

        // Change the decryption key so that decryption should fail
        unsafe { DEC_KEY = b"wrong_passwhichneedstobe32bytes!" };
        let image_layer_sym_key: &[u8] = opts_data;
        let cipher = Aes256Gcm::new(Key::from_slice(unsafe { ENC_KEY }));
        let nonce = Nonce::from_slice(b"unique nonce");
        let wrapped_key = cipher.encrypt(nonce, image_layer_sym_key).unwrap();

        let ap = AnnotationPacket {
            key_url: "https://key-provider/key-uuid".to_string(),
            wrapped_key,
            wrap_type: "AES".to_string(),
        };

        let serialized_ap = serde_json::to_vec(&ap).unwrap();
        assert!(keyprovider_key_wrapper.unwrap_keys(&dc, &serialized_ap).is_err());
    }

    // Run a mock grpc server
    fn start_grpc_server(sock_address :String) {
        tokio::spawn(async move{
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
        // sleep for few seconds so that grpc server bootstraps
        start_grpc_server("127.0.0.1:8990".to_string());
        sleep(Duration::from_secs(1));
        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs { cmd: None, grpc: Some("tcp://127.0.0.1:8990".to_string()) };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), None);

        // Prepare encryption config params
        let opts_data = b"symmetric_key";
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper.wrap_keys(&ec, opts_data).is_ok());
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, opts_data);

        // Perform decryption-config params
        let mut dc_params = vec![];
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        let json_string: &[u8] = &key_wrap_output_result.unwrap();

        // Perform unwrapkey operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, json_string);
        let unwrapped_key: &[u8] = &key_wrap_output_result.unwrap();

        assert_eq!(opts_data, unwrapped_key);
        // runtime shutdown for stopping grpc server
        rt.shutdown_background();
    }

    #[test]
    fn test_key_provider_grpc_http_success() {
        let rt = Runtime::new().unwrap();
        let _guard = rt.enter();
        // sleep for few seconds so that grpc server bootstraps
        start_grpc_server("127.0.0.1:8991".to_string());
        sleep(Duration::from_secs(1));
        unsafe {
            ENC_KEY = b"passphrasewhichneedstobe32bytes!";
            DEC_KEY = b"passphrasewhichneedstobe32bytes!";
        }

        let mut provider = HashMap::new();
        let attrs = config::KeyProviderAttrs { cmd: None, grpc: Some("http://127.0.0.1:8991".to_string()) };
        provider.insert(String::from("provider"), attrs.clone());
        let keyprovider_key_wrapper = new_key_wrapper("keyprovider".to_string(), attrs.clone(), None);

        // Prepare encryption config params
        let opts_data = b"symmetric_key";
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());
        assert!(keyprovider_key_wrapper.wrap_keys(&ec, opts_data).is_ok());
        let key_wrap_output_result = keyprovider_key_wrapper.wrap_keys(&ec, opts_data);

        // Perform decryption-config params
        let mut dc_params = vec![];
        dc_params.push(param);
        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());
        let json_string: &[u8] = &key_wrap_output_result.unwrap();

        // Perform unwrapkey operation
        let key_wrap_output_result = keyprovider_key_wrapper.unwrap_keys(&dc, json_string);
        let unwrapped_key: &[u8] = &key_wrap_output_result.unwrap();

        assert_eq!(opts_data, unwrapped_key);
        // runtime shutdown for stopping grpc server
        rt.shutdown_background();
    }
}