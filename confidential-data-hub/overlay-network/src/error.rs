//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, OverlayNetworkError>;

#[derive(Error, Debug)]
pub enum OverlayNetworkError {
    #[error("Overlay network init failed: {0}")]
    Init(String),

    #[error("Overlay network feature not enabled")]
    NotEnabled(),

    #[error(
        "Mesh netmask (user-configured) and worker netmask (assigned by \
           the control plane) should match: {0}"
    )]
    NetmaskMismatch(String),

    #[error("Unable to get iface details: {0}")]
    IfaceDetails(String),

    #[error("KBS client initialization failed")]
    KbsClient {
        #[source]
        source: kms::Error,
    },

    #[error("Get secret failed")]
    GetSecret {
        #[source]
        source: kms::Error,
    },

    #[error("Failed to parse KBS response")]
    ResponseParse(#[from] serde_json::Error),

    #[error("Error while handling yaml data")]
    SerdeYmlFail(#[from] serde_yml::Error),

    #[error("I/O error")]
    IoError(#[from] std::io::Error),

    #[error("Error parsing Ipv4Addr")]
    AddrParseFail(#[from] std::net::AddrParseError),
}
