// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use oci_client::ParseError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, PullImageError>;

#[derive(Error, Debug)]
pub enum PullImageError {
    #[error("Illegal image reference")]
    IllegalImageReference {
        #[source]
        source: ParseError,
    },

    #[error("failed to compose a legal image reference with given registry configuration")]
    IllegalRegistryConfigurationFormat {
        #[source]
        source: anyhow::Error,
    },

    #[error(
        "Failed to pull image {original_image_url} from all mirror/mapping locations or original location: {tried_list}"
    )]
    AllTasksTried {
        original_image_url: String,
        tried_list: String,
    },

    #[error("Illegal registry auth for image {image} from {auth_source}")]
    IllegalRegistryAuth { image: String, auth_source: String },

    #[error("Failed to pull image manifest")]
    FailedToPullManifest {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to create bundle")]
    FailedToCreateBundle {
        #[source]
        source: anyhow::Error,
    },

    #[cfg(feature = "signature")]
    #[error("Image policy rejected")]
    SignatureValidationFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("{0} layers are not pulled successfully")]
    NotAllUniqueLayersPulled(usize),

    #[error("Failed to pull layers")]
    PullLayersFailed {
        #[source]
        source: anyhow::Error,
    },

    #[cfg(feature = "nydus")]
    #[error("Failed to pull nydus image")]
    NydusImagePullFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Internal error")]
    Internal {
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to get a proper image decryption key")]
    ImageDecryptionKeyNotFound {
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to decrypt image")]
    ImageDecryptionFailed {
        #[source]
        source: anyhow::Error,
    },
}
