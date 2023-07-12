// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for signature verification.

#[cfg(feature = "getresource")]
use image_rs::image::ImageClient;
#[cfg(feature = "getresource")]
use serial_test::serial;
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
        image_ref: "quay.io/kata-containers/confidential-containers:cosign-signed",
        allow: true,
        signing_scheme: SigningName::Cosign,
        description: "Allow pulling an unencrypted signed image with cosign-signed signature",
    },
    #[cfg(feature = "signature-cosign")]
    _TestItem {
        image_ref: "quay.io/kata-containers/confidential-containers:cosign-signed-key2",
        allow: false,
        signing_scheme: SigningName::Cosign,
        description: "Deny pulling an unencrypted signed image by cosign using a wrong public key",
    },
];

#[cfg(feature = "getresource")]
const POLICY_URI: &str = "kbs:///default/security-policy/test";

#[cfg(feature = "getresource")]
const SIGSTORE_CONFIG_URI: &str = "kbs:///default/sigstore-config/test";

/// image-rs built without support for cosign image signing cannot use a policy that includes a type that
/// uses cosign (type: sigstoreSigned), even if the image being pulled is not signed using cosign.
/// https://github.com/confidential-containers/attestation-agent/blob/main/src/kbc_modules/sample_kbc/policy.json
#[cfg(feature = "getresource")]
#[tokio::test]
#[serial]
async fn signature_verification() {
    common::prepare_test().await;
    // Init AA
    let _aa = common::start_attestation_agent()
        .await
        .expect("Failed to start attestation agent!");

    for test in &_TESTS {
        // clean former test files
        common::clean_configs()
            .await
            .expect("Delete configs failed.");

        // Init tempdirs
        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());

        // a new client for every pulling, avoid effection
        // of cache of old client.
        let mut image_client = ImageClient::default();

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
                &None,
                &Some(common::AA_PARAMETER),
            )
            .await;
        if cfg!(all(feature = "snapshot-overlayfs",)) {
            assert_eq!(
                _res.is_ok(),
                test.allow,
                "Test: {}, Signing scheme: {}, {:?}",
                test.description,
                test.signing_scheme.to_string(),
                _res
            );
        }
    }

    common::clean().await;
}
