// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Overall
//! For signature verification in Confidential-Containers.
//!
//! # Usage
//! create a new agent
//!
//! ```no_run
//! use anyhow::{anyhow, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // For example kbc
//!     let aa_kbc_params = "null_kbc::null";
//!     // Check an image
//!     signature::allows_image(
//!         "<image-url>",
//!         "<image-digest>",
//!         aa_kbc_params
//!         )
//!         .await
//!         .map_err(|e| anyhow!("Security validate failed: {:?}", e))?;
//!
//!     Ok(())
//! }
//! ```

#[macro_use]
extern crate strum;

use anyhow::Result;

pub mod agent;
pub mod image;
pub mod mechanism;
pub mod payload;
pub mod policy;

/// `allows_image` will check all the `PolicyRequirements` suitable for
/// the given image. The `PolicyRequirements` is defined in
/// [`agent::POLICY_FILE_PATH`] and may include signature verification.
pub async fn allows_image(image_url: &str, image_digest: &str, aa_kbc_params: &str) -> Result<()> {
    let mut sig_agent = agent::Agent::new(aa_kbc_params).await?;
    sig_agent.allows_image(image_url, image_digest).await
}
