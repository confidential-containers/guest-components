// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for signature verification.

use std::process::Command;

use image_rs::image::ImageClient;

mod common;

/// Name of different signing schemes.
const SIMPLE_SIGNING: &str = "Simple Signing";
const NONE_SIGNING: &str = "None";

/// Script for preparing Simple Signing GPG signature file.
const SIGNATURE_SCRIPT: &str = "scripts/install_test_signatures.sh";

/// Parameter `decrypt_config` provided for `ImageClient`.
const AA_PARAMETERS: &str = "provider:attestation-agent:sample_kbc::null";

struct TestItem<'a, 'b, 'c> {
    image_ref: &'a str,
    allow: bool,
    signing_scheme: &'b str,
    description: &'c str,
}

#[tokio::test]
async fn test_signature_verification() {
    Command::new(SIGNATURE_SCRIPT)
        .arg("install")
        .output()
        .expect("Install GPG signature file failed.");

    let tests = [
        TestItem {
            image_ref: "quay.io/prometheus/busybox:latest",
            allow: true,
            signing_scheme: NONE_SIGNING,
            description:
                "Allow pulling an unencrypted unsigned image from an unprotected registry.",
        },
        TestItem {
            image_ref: "quay.io/kata-containers/confidential-containers:signed",
            allow: true,
            signing_scheme: SIMPLE_SIGNING,
            description: "Allow pulling a unencrypted signed image from a protected registry.",
        },
        TestItem {
            image_ref: "quay.io/kata-containers/confidential-containers:unsigned",
            allow: false,
            signing_scheme: NONE_SIGNING,
            description: "Deny pulling an unencrypted unsigned image from a protected registry.",
        },
        TestItem {
            image_ref: "quay.io/kata-containers/confidential-containers:other_signed",
            allow: false,
            signing_scheme: SIMPLE_SIGNING,
            description: "Deny pulling an unencrypted signed image with an unknown signature",
        },
    ];

    // Init AA
    let mut aa = common::start_attestation_agent().expect("Failed to start attestation agent!");

    // Init tempdirs
    let work_dir = tempfile::tempdir().unwrap();
    std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());

    let bundle_dir = tempfile::tempdir().unwrap();

    for test in &tests {
        // clean former test files, which will help to test
        // a full interaction with sample-kbc.
        common::clean_configs()
            .await
            .expect("Delete configs failed.");

        // a new client for every pulling, avoid effection
        // of cache of old client.
        let mut image_client = ImageClient::default();

        // enable signature verification
        image_client.config.security_validate = true;

        let res = image_client
            .pull_image(
                test.image_ref,
                bundle_dir.path(),
                &None,
                &Some(AA_PARAMETERS),
            )
            .await;
        match test.allow {
            true => {
                assert!(
                    res.is_ok(),
                    "Test: {}, Signing scheme: {}",
                    test.description,
                    test.signing_scheme
                );
            }
            false => assert!(
                res.is_err(),
                "Test: {}, Signing scheme: {}",
                test.description,
                test.signing_scheme
            ),
        };
    }

    // kill AA when the test is finished
    aa.kill().expect("Failed to stop attestation agent!");
}
