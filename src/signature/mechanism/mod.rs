// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Signing schemes
//! different signatures defination and the top level interfaces.
//!
//! ### Design
//! Due to the format of policy requirement in
//! <https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements>,
//! a signing scheme is also treated as a policy
//! requirement. To support different kinds of signing
//! schemes, we use a trait [`SignScheme`] to define. The trait object
//! will be included into [`crate::policy::PolicyReqType`].

use anyhow::*;
use async_trait::async_trait;
use oci_distribution::secrets::RegistryAuth;

use crate::config::Paths;

use super::image::Image;

pub mod cosign;
pub mod simple;

/// The interface of a signing scheme
#[async_trait]
pub trait SignScheme: Send + Sync {
    /// Do initialization jobs for this scheme. This may include the following
    /// * preparing runtime directories for storing signatures, configurations, etc.
    /// * gathering necessary files.
    async fn init(&mut self, config: &Paths) -> Result<()>;

    /// Judge whether an image is allowed by this SignScheme.
    async fn allows_image(&self, image: &mut Image, auth: &RegistryAuth) -> Result<()>;
}
