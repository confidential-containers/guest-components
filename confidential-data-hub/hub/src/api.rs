// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;

use crate::Result;
use storage::volume_type::Storage;

/// The APIs of the DataHub. See
/// <https://github.com/confidential-containers/documentation/issues/131> for
/// more information.
#[async_trait]
pub trait DataHub {
    /// Unseal the given sealed secret. The sealed secret format is defined
    /// in <https://github.com/confidential-containers/guest-components/blob/main/confidential-data-hub/docs/SEALED_SECRET.md>
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>>;

    /// Unwrap the LEK inside the image annotation. This API is used in
    /// `ocicrypt`'s `KeyProvider`. The received parameter should be an
    /// AnnotationPacket. Please refer to
    /// <https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/IMAGE_ENCRYPTION.md#annotation-packet>
    async fn unwrap_key(&self, annotation: &[u8]) -> Result<Vec<u8>>;

    /// Get the resource due to the given KBS Resource URI. The KBS Resource
    /// URI is defined in
    /// <https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/KBS_URI.md>
    async fn get_resource(&self, uri: String) -> Result<Vec<u8>>;

    async fn secure_mount(&self, storage: Storage) -> Result<String>;

    /// Pull image of image url (reference), and place the merged layers in the `bundle_path/rootfs`
    async fn pull_image(&self, _image_url: &str, _bundle_path: &str) -> Result<String>;
}
