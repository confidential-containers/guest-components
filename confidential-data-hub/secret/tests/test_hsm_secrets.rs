// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    fs::File,
    io::{Read, Write},
    process::Command,
};

use assert_cmd::prelude::*;
use rand::{distributions::Uniform, Rng};
use tempfile::tempdir;

#[test]
#[ignore]
#[cfg(feature = "aliyun")]
fn test_cli_envelope_secret_lifetime_aliyun() {
    let base_dir = "tests/envelope_secret_aliyun_config_sample/";
    let key_id = "alias/test_key_id";
    let sub_cmd = vec![
        "ali",
        "--password-file-path",
        "tests/envelope_secret_aliyun_config_sample/password_KAAP.2bc4____.json",
        "--kms-instance-id",
        "kst-bjj6****",
        "--client-key-file-path",
        "tests/envelope_secret_aliyun_config_sample/clientKey_KAAP.2bc4____.json",
        "--cert-path",
        "tests/envelope_secret_aliyun_config_sample/PrivateKmsCA_kst-bjj6____.pem",
    ];
    key_lifetime(base_dir, key_id, sub_cmd);
}

#[test]
#[ignore]
#[cfg(feature = "ehsm")]
fn test_cli_envelope_secret_lifetime_ehsm() {
    let base_dir = "tests/envelope_secret_ehsm_config_sample/";
    let key_id = "39c8____";
    let sub_cmd = vec![
        "ehsm",
        "--credential-file-path",
        "tests/envelope_secret_ehsm_config/credential_16f3____.json",
        "--endpoint",
        "https://1.2.3.4:9000",
    ];
    key_lifetime(base_dir, key_id, sub_cmd);
}

fn key_lifetime(base_dir: &str, key_id: &str, sub_cmd: Vec<&str>) {
    let dir = tempdir().expect("create temdir fail");
    let dir_path = dir.path();

    let original_secret_file_path = dir_path.join("plaintext").to_str().unwrap().to_owned();
    let sealed_secret_file_path = dir_path
        .join("sealed_secret.json")
        .to_owned()
        .to_str()
        .unwrap()
        .to_owned();
    let unsealed_secret_file_path = format!("{}.unsealed", &sealed_secret_file_path);

    // create random secret
    let secret = create_random_secret();
    File::create(&original_secret_file_path)
        .expect("create 'secret_file' fail")
        .write_all(&secret)
        .expect("write 'secret_file' fail");

    // seal secret with 'secret_cli'
    let seal_secret_output = Command::cargo_bin("secret_cli")
        .expect("init 'cargo_bin' fail")
        .arg("seal")
        .arg("envelope")
        .args(["--file-path", &original_secret_file_path])
        .args(["--key-id", key_id])
        .args(sub_cmd)
        .output()
        .expect("Failed to execute seal secret");

    File::create(&sealed_secret_file_path)
        .expect("create 'sealed secret_file' fail")
        .write_all(&seal_secret_output.stdout)
        .expect("write 'sealed_secret_file' fail");

    assert!(seal_secret_output.status.success());

    // unseal secret with 'secret_cli'
    let unseal_secret_output = Command::cargo_bin("secret_cli")
        .expect("init 'cargo_bin' fail")
        .arg("unseal")
        .args(["--file-path", &sealed_secret_file_path])
        .args(["--key-path", &base_dir])
        .output()
        .expect("Failed to execute unseal secret");

    assert!(unseal_secret_output.status.success());

    // compare original secret and unsealed secret
    let mut original_secret_file =
        File::open(&original_secret_file_path).expect("open original_secret_file fail");
    let mut original_secret = Vec::new();
    original_secret_file
        .read_to_end(&mut original_secret)
        .expect("read original_secret_file fail");

    let mut unsealed_secret_file =
        File::open(&unsealed_secret_file_path).expect("open unsealed_secret_file fail");
    let mut unsealed_secret = Vec::new();
    unsealed_secret_file
        .read_to_end(&mut unsealed_secret)
        .expect("read unsealed_secret_file fail");

    assert_eq!(original_secret, unsealed_secret);
}

fn create_random_secret() -> Vec<u8> {
    let data_length = 10;

    let mut rng = rand::thread_rng();

    let data: Vec<u8> = (0..data_length)
        .map(|_| rng.sample(Uniform::new_inclusive(0, 255)))
        .collect();

    data
}
