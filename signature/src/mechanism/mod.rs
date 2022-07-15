// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use anyhow::*;

use crate::Image;

use self::simple::SimpleParameters;

pub mod simple;

/// Signing schemes.
/// * `SimpleSigning`: Redhat simple signing.
#[derive(Deserialize, Debug, PartialEq, Serialize)]
#[serde(tag = "scheme")]
pub enum SignScheme {
    #[serde(rename = "simple")]
    SimpleSigning(SimpleParameters),
}

// TODO: Add more signature mechanism.
//
// Refer to issue: https://github.com/confidential-containers/image-rs/issues/7

impl SignScheme {
    pub fn allows_image(&self, image: &mut Image) -> Result<()> {
        match self {
            SignScheme::SimpleSigning(parameters) => {
                simple::judge_signatures_accept(&parameters, image)
            }
        }
    }
}