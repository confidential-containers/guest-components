// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::signatures;
use anyhow::{anyhow, Result};
use oci_distribution::Reference;
use url::Url;

pub mod digest;

use digest::Digest;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum TransportName {
    #[strum(to_string = "docker")]
    Docker,
    #[strum(to_string = "dir")]
    Dir,
}

// Image contains information about the image which may be used in signature verification.
pub struct Image {
    pub reference: Reference,
    // digest format: "digest-algorithm:digest-value"
    pub manifest_digest: Digest,

    // Try signature extensions in registry before using the sigstore.
    // (https://github.com/containers/image/issues/384)
    //
    // FIXME: now don't support, always set to false.
    //
    // issue: https://github.com/confidential-containers/image-rs/issues/12
    pub registry_xrss_api_support: bool,

    sigstore_base_url: Option<Url>,
    signatures: Vec<Vec<u8>>,
}

impl Image {
    pub fn default_with_reference(image_ref: Reference) -> Self {
        Image {
            reference: image_ref,
            manifest_digest: Digest::default(),
            registry_xrss_api_support: false,
            sigstore_base_url: None,
            signatures: Vec::default(),
        }
    }

    pub fn transport_name(&self) -> String {
        // FIXME: Now only support "docker" transport (and it is hardcoded).
        // TODO: support "dir" transport.
        //
        // issue: https://github.com/confidential-containers/image-rs/issues/11
        TransportName::Docker.to_string()
    }

    pub fn set_manifest_digest(&mut self, digest: &str) -> Result<()> {
        self.manifest_digest = Digest::try_from(digest)?;
        Ok(())
    }

    pub fn set_sigstore_base_url(&mut self, url_string: String) -> Result<()> {
        let url = Url::parse(&url_string)?;
        self.sigstore_base_url = Some(url);
        Ok(())
    }

    pub fn get_sigstore_base_url_string(&self) -> String {
        match &self.sigstore_base_url {
            Some(url) => url.to_string(),
            None => "".to_string(),
        }
    }

    pub fn signatures(&mut self) -> Result<Vec<Vec<u8>>> {
        if self.signatures.is_empty() {
            return self.internal_signatures();
        }

        Ok(self.signatures.clone())
    }

    fn internal_signatures(&mut self) -> Result<Vec<Vec<u8>>> {
        // Get image digest (manifest digest)
        let image_digest = if !self.manifest_digest.is_empty() {
            self.manifest_digest.clone()
        } else if let Some(d) = self.reference.digest() {
            Digest::try_from(d)?
        } else {
            return Err(anyhow!("Missing image digest"));
        };

        // Format the sigstore name: `image-repository@digest-algorithm=digest-value`.
        let sigstore_name = signatures::format_sigstore_name(&self.reference, image_digest);

        // If the registry support `X-Registry-Supports-Signatures` API extension,
        // try to get signatures from the registry first.
        // Else, get signatures from "sigstore" according to the sigstore config file.
        if self.registry_xrss_api_support {
            // TODO: Add get signatures from registry X-R-S-S API extension.
            return Err(anyhow!(
                "Now not support get signatures from registry X-R-S-S API extension."
            ));
        } else if self.sigstore_base_url.is_none() {
            let sigstore_config =
                signatures::SigstoreConfig::new_from_configs(signatures::SIGSTORE_CONFIG_DIR)?;
            if let Some(base_url) = sigstore_config.base_url(&self.reference)? {
                self.set_sigstore_base_url(base_url)?;
            }
        }

        let sigstore = format!(
            "{}/{}",
            &self.get_sigstore_base_url_string(),
            &sigstore_name
        );
        let sigstore_uri = url::Url::parse(&sigstore[..])
            .map_err(|e| anyhow!("Failed to parse sigstore_uri: {:?}", e))?;

        self.signatures = signatures::get_sigs_from_specific_sigstore(sigstore_uri)?;

        Ok(self.signatures.clone())
    }
}

// Get repository full name:
// `registry-name/repository-name`
pub fn get_image_repository_full_name(image_ref: &Reference) -> String {
    if image_ref.registry().is_empty() {
        image_ref.repository().to_string()
    } else {
        format!("{}/{}", image_ref.registry(), image_ref.repository())
    }
}

// Returns a list of other policy configuration namespaces to search.
pub fn get_image_namespaces(image_ref: &Reference) -> Vec<String> {
    // Look for a match of the repository, and then of the possible parent
    // namespaces. Note that this only happens on the expanded host names
    // and repository names, i.e. "busybox" is looked up as "docker.io/library/busybox",
    // then in its parent "docker.io/library"; in none of "busybox",
    // un-namespaced "library" nor in "" supposedly implicitly representing "library/".
    //
    // image_full_name == host_name + "/" + repository_name, so the last
    // iteration matches the host name (for any namespace).
    let mut res = Vec::new();
    let mut name: String = get_image_repository_full_name(image_ref);

    loop {
        res.push(name.clone());
        match name.rsplit_once('/') {
            None => break,
            Some(n) => {
                name = n.0.to_string();
            }
        }
    }

    // Strip port number if any, before appending to res slice.
    // Currently, the most compatible behavior is to return
    // example.com:8443/ns, example.com:8443, *.com.
    // If a port number is not specified, the expected behavior would be
    // example.com/ns, example.com, *.com
    if let Some(n) = name.rsplit_once(':') {
        name = n.0.to_string();
    }

    // Append wildcarded domains to res slice
    loop {
        match name.split_once('.') {
            None => break,
            Some(n) => {
                name = n.1.to_string();
            }
        }
        res.push(format!("*.{}", name.clone()));
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_image_get_signature() {
        let image_reference = "quay.io/ali_os_security/alpine:latest";
        let current_dir = env::current_dir().expect("not found path");
        let sigstore_base_url =
            format!("file://{}/fixtures/sigstore", current_dir.to_str().unwrap());

        let reference = Reference::try_from(image_reference).unwrap();
        let mut image = Image {
            reference,
            manifest_digest: Digest::try_from(
                "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a",
            )
            .unwrap(),
            sigstore_base_url: Some(Url::parse(&sigstore_base_url).unwrap()),
            registry_xrss_api_support: false,
            signatures: Vec::default(),
        };
        assert_eq!(
            ::std::fs::read("./fixtures/signatures/signature-1").unwrap(),
            image.signatures().unwrap()[0]
        );
    }

    #[test]
    fn test_parse_image_reference() {
        let test_cases: Vec<String> = vec![
            "",
            ":justtag",
            "docker.io//library///repo:tag",
            "docker.io/library/repo::tag",
            "docker.io/library/",
            "repo@@@sha256:ffffffffffffffffffffffffffffffffff",
            "*:tag",
            "***/&/repo:tag",
            "@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "repo@sha256:ffffffffffffffffffffffffffffffffff",
            "validname@invaliddigest:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "Uppercase:tag",
            "test:5000/Uppercase/lowercase:tag",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aa/asdf$$^/aa",
        ].iter()
        .map(|case| case.to_string())
        .collect();

        for case in test_cases.iter() {
            assert!(Reference::try_from(case.as_str()).is_err());
        }
    }

    #[test]
    fn test_get_image_id_and_ns() {
        #[derive(Debug)]
        struct TestData<'a> {
            image_reference: Reference,
            image_namespace: Vec<&'a str>,
        }

        let tests = &[
            TestData {
                image_reference: Reference::try_from(
                        "docker.io/opensuse/leap:15.3"
                    ).unwrap(),
                image_namespace: vec![
                    "docker.io/opensuse/leap",
                    "docker.io/opensuse",
                    "docker.io",
                    "*.io"
                    ],
            },
            TestData {
                image_reference: Reference::try_from(
                        "test:5000/library/busybox:latest"
                    ).unwrap(),
                image_namespace: vec![
                    "test:5000/library/busybox",
                    "test:5000/library",
                    "test:5000"
                    ],
            },
            TestData {
                image_reference: Reference::try_from(
                        "test:5000/library/busybox@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    ).unwrap(),
                image_namespace: vec![
                    "test:5000/library/busybox",
                    "test:5000/library",
                    "test:5000"
                    ],
            },
            TestData {
                image_reference: Reference::try_from(
                        "registry.access.redhat.com/busybox:latest"
                    ).unwrap(),
                image_namespace: vec![
                    "registry.access.redhat.com/busybox",
                    "registry.access.redhat.com",
                    "*.access.redhat.com",
                    "*.redhat.com",
                    "*.com"
                    ],
            },
        ];

        for test_case in tests.iter() {
            assert_eq!(
                test_case.image_reference.to_string(),
                test_case.image_reference.whole()
            );

            let mut image_namespace_strings = Vec::new();
            for name in test_case.image_namespace.iter() {
                image_namespace_strings.push(name.to_string());
            }

            assert_eq!(
                image_namespace_strings,
                get_image_namespaces(&test_case.image_reference)
            );
        }
    }
}
