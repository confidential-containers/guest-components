// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for signature verification.

use strum_macros::{Display, EnumString};

pub mod common;

/// Name of different signing schemes.
#[derive(EnumString, Display, Debug, PartialEq)]
pub enum SigningName {
    #[strum(serialize = "Simple Signing")]
    SimpleSigning,
    #[strum(serialize = "None")]
    None,
    #[strum(serialize = "Cosign")]
    Cosign,
}

struct _TestItem<'a, 'b> {
    image_ref: &'a str,
    allow: bool,
    signing_scheme: SigningName,
    description: &'b str,
}

const _TEST_ITEMS: usize = cfg!(feature = "signature-cosign") as usize * 2
    + cfg!(feature = "signature-simple") as usize * 2
    + 2;

#[cfg(feature = "signature-simple-xrss")]
const _TEST_ITEMS_XRSS: usize = 3;

/// Four test cases.
const _TESTS: [_TestItem; _TEST_ITEMS] = [
    _TestItem {
        image_ref: "quay.io/prometheus/busybox:latest",
        allow: true,
        signing_scheme: SigningName::None,
        description: "Allow pulling an unencrypted unsigned image from an unprotected registry.",
    },
    #[cfg(feature = "signature-simple")]
    _TestItem {
        image_ref: "quay.io/kata-containers/confidential-containers:signed",
        allow: true,
        signing_scheme: SigningName::SimpleSigning,
        description: "Allow pulling a unencrypted signed image from a protected registry.",
    },
    _TestItem {
        image_ref: "quay.io/kata-containers/confidential-containers:unsigned",
        allow: false,
        signing_scheme: SigningName::None,
        description: "Deny pulling an unencrypted unsigned image from a protected registry.",
    },
    #[cfg(feature = "signature-simple")]
    _TestItem {
        image_ref: "quay.io/kata-containers/confidential-containers:other_signed",
        allow: false,
        signing_scheme: SigningName::SimpleSigning,
        description: "Deny pulling an unencrypted signed image with an unknown signature",
    },
    #[cfg(feature = "signature-cosign")]
    _TestItem {
        image_ref: "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        allow: true,
        signing_scheme: SigningName::Cosign,
        description: "Allow pulling an unencrypted signed image with cosign-signed signature",
    },
    #[cfg(feature = "signature-cosign")]
    _TestItem {
        image_ref: "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed-key2",
        allow: false,
        signing_scheme: SigningName::Cosign,
        description: "Deny pulling an unencrypted signed image by cosign using a wrong public key",
    },
];

#[cfg(feature = "signature-simple-xrss")]
const _TESTS_XRSS: [_TestItem; _TEST_ITEMS_XRSS] = [
    _TestItem {
        image_ref: "quay.io/kata-containers/confidential-containers:signed",
        allow: false,
        signing_scheme: SigningName::SimpleSigning,
        description: "Deny pulling an unencrypted signed image with no local sigstore and a registry that does not support the X-R-S-S API extension",
    },
    _TestItem {
        image_ref: "uk.icr.io/kata-containers/busybox:signed-latest",
        allow: true,
        signing_scheme: SigningName::SimpleSigning,
        description: "Allow pulling an unencrypted signed image from a protected registry that supports the X-R-S-S API extension with no local sigstore",
    },
    _TestItem {
        image_ref: "uk.icr.io/kata-containers/busybox:unsigned-1.35",
        allow: false,
        signing_scheme: SigningName::SimpleSigning,
        description: "Deny pulling an unencrypted and unsigned image from a protected registry that supports the X-R-S-S API extension with no local sigstore",
    },
];

#[cfg(all(
    feature = "getresource",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
const POLICY_URI: &str = "kbs:///default/security-policy/test";

#[cfg(all(
    feature = "getresource",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
const SIGSTORE_CONFIG_URI: &str = "kbs:///default/sigstore-config/test";

/// image-rs built without support for cosign image signing cannot use a policy that includes a type that
/// uses cosign (type: sigstoreSigned), even if the image being pulled is not signed using cosign.
/// https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/kbc/src/sample_kbc/policy.json
#[cfg(all(
    feature = "getresource",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
#[tokio::test]
#[serial_test::serial]
async fn signature_verification() {
    do_signature_verification_tests(&_TESTS, common::OFFLINE_FS_KBC_RESOURCES_FILE, &None).await;
}

#[cfg(all(
    feature = "signature-simple-xrss",
    feature = "getresource",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
#[tokio::test]
#[serial_test::serial]
async fn signature_verification_xrss() {
    match std::env::var("AUTH_PASSWORD") {
        Ok(auth_password) => match !auth_password.is_empty() {
            true => {
                let auth = format!("iamapikey:{}", auth_password);
                let auth_info = &Some(auth.as_str());
                do_signature_verification_tests(
                    &_TESTS_XRSS,
                    common::AA_OFFLINE_FS_KBC_RESOURCES_FILE_XRSS,
                    auth_info,
                )
                .await;
            }
            false => {
                println!("Skipping xrss test cases because the test cases require authentication and no AUTH is set in the environment");
            }
        },
        Err(_) => {
            println!("Skipping xrss test cases because the test cases require authentication and no AUTH is set in the environment");
        }
    }
}

#[cfg(all(
    feature = "getresource",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
async fn do_signature_verification_tests(
    tests: &[_TestItem<'_, '_>],
    offline_fs_kbc_resources: &str,
    auth_info: &Option<&str>,
) {
    common::prepare_test(offline_fs_kbc_resources).await;
    // Init CDH
    let _cdh = common::start_confidential_data_hub()
        .await
        .expect("Failed to start confidential data hub!");

    for test in tests {
        let mut test_auth_info = auth_info;
        if test.image_ref.to_string().contains("quay") {
            test_auth_info = &None;
        }

        // clean former test files
        common::clean_configs()
            .await
            .expect("Delete configs failed.");

        // Init tempdirs
        let work_dir = tempfile::tempdir().unwrap();

        // a new client for every pulling, avoid effection
        // of cache of old client.
        let mut image_client = image_rs::image::ImageClient::new(work_dir.path().to_path_buf());

        // enable signature verification
        image_client.config.security_validate = true;

        // set the image security policy
        image_client.config.file_paths.policy_path = POLICY_URI.into();

        #[cfg(feature = "signature-simple")]
        {
            image_client.config.file_paths.sigstore_config = SIGSTORE_CONFIG_URI.into();
        }

        let bundle_dir = tempfile::tempdir().unwrap();

        let _res = image_client
            .pull_image(
                test.image_ref,
                bundle_dir.path(),
                test_auth_info,
                &Some(common::AA_PARAMETER),
            )
            .await;
        if cfg!(all(feature = "snapshot-overlayfs",)) {
            assert_eq!(
                _res.is_ok(),
                test.allow,
                "Test: {}, Signing scheme: {}, {:?}",
                test.description,
                test.signing_scheme,
                _res
            );
        }
    }

    common::clean().await;
}
