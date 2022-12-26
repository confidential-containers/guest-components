// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

/// `AnnotationPacket` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/attestation-agent/issues/113>
#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}
