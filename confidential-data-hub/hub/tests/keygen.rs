// Copyright (c) 2024 Red Hat, Inc
//
// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::collections::HashMap;
use tempfile::TempDir;

const SIGNING_CREDENTIALS_PATH: &str = "/run/confidential-containers/cdh/sealed-secret";

/// End-to-end test: generate a keypair, seal a vault secret, unseal it, and
/// verify the plaintext matches. Uses `offline_fs_kbc` with
/// `OFFLINE_FS_KBC_EXTRA_FILE_PATH` so no writes to /etc/ are needed.
///
/// Must run as root (writes to /run/) — intended for CI containers.
#[test]
fn seal_unseal_vault_e2e() {
    let tmp = TempDir::new().unwrap();
    let kid = "e2e-test-key";
    let secret_plaintext = b"super-secret-value-42";
    let resource_path = "default/sealed-secret/e2e-test";
    let resource_uri = format!("kbs:///{resource_path}");

    // 1. Generate a signing keypair
    Command::cargo_bin("secret")
        .unwrap()
        .args(["keygen", "--kid", kid, "--output-dir"])
        .arg(tmp.path())
        .assert()
        .success();

    let private_jwk_path = tmp.path().join(format!("{kid}-private.json"));
    let public_jwk_path = tmp.path().join(format!("{kid}-public.json"));
    assert!(private_jwk_path.exists());
    assert!(public_jwk_path.exists());

    // Verify key structure
    let private_jwk: Value =
        serde_json::from_str(&std::fs::read_to_string(&private_jwk_path).unwrap()).unwrap();
    assert_eq!(private_jwk["kty"], "EC");
    assert_eq!(private_jwk["crv"], "P-256");
    assert!(private_jwk["d"].is_string(), "private key must contain d");

    let public_jwk: Value =
        serde_json::from_str(&std::fs::read_to_string(&public_jwk_path).unwrap()).unwrap();
    assert!(public_jwk["d"].is_null(), "public key must not contain d");

    // 2. Provision the secret to a temp file for offline_fs_kbc
    let resources_path = tmp.path().join("offline-resources.json");
    let mut resources: HashMap<String, String> = HashMap::new();
    resources.insert(resource_path.to_string(), STANDARD.encode(secret_plaintext));
    std::fs::write(&resources_path, serde_json::to_string(&resources).unwrap()).unwrap();

    // 3. Provision the public key for signature verification
    std::fs::create_dir_all(SIGNING_CREDENTIALS_PATH)
        .expect("failed to create signing credentials dir (need root?)");
    std::fs::copy(
        &public_jwk_path,
        format!("{SIGNING_CREDENTIALS_PATH}/{kid}"),
    )
    .unwrap();

    // 4. Seal the vault secret
    let seal_output = Command::cargo_bin("secret")
        .unwrap()
        .args([
            "seal",
            "--signing-kid",
            kid,
            "--signing-jwk-path",
            private_jwk_path.to_str().unwrap(),
            "vault",
            "--resource-uri",
            &resource_uri,
            "--provider",
            "kbs",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&seal_output.stdout);
    let stderr = String::from_utf8_lossy(&seal_output.stderr);
    assert!(
        seal_output.status.success(),
        "seal failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let sealed_secret = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("sealed."))
        .expect("seal output must contain a line starting with 'sealed.'");

    // 5. Write the sealed secret to a file and unseal it
    let sealed_path = tmp.path().join("sealed.txt");
    std::fs::write(&sealed_path, sealed_secret).unwrap();

    Command::cargo_bin("secret")
        .unwrap()
        .env(
            "OFFLINE_FS_KBC_EXTRA_FILE_PATH",
            resources_path.to_str().unwrap(),
        )
        .args([
            "unseal",
            "--file-path",
            sealed_path.to_str().unwrap(),
            "--aa-kbc-params",
            "offline_fs_kbc::null",
        ])
        .assert()
        .success();

    // 6. Verify the unsealed secret matches the original plaintext
    let unsealed_path = tmp.path().join("sealed.txt.unsealed");
    assert!(unsealed_path.exists(), "unsealed file must be created");
    let unsealed = std::fs::read(&unsealed_path).unwrap();
    assert_eq!(unsealed, secret_plaintext);
}
