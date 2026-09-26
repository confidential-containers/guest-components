// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Error;
use strum::EnumString;

#[cfg(feature = "kbs")]
pub mod kbs;

#[cfg(feature = "coco_as")]
pub mod coco_as;

#[cfg(feature = "ccm_as")]
pub mod ccm_as;

fn make_error(_: &str) -> Error {
    Error::msg("Invalid resource type")
}

#[derive(EnumString, Clone, Copy)]
#[strum(parse_err_ty = anyhow::Error, parse_err_fn = make_error)]
pub enum TokenType {
    #[cfg(feature = "kbs")]
    #[strum(serialize = "kbs")]
    Kbs,

    #[cfg(feature = "coco_as")]
    #[strum(serialize = "coco_as")]
    CoCoAS,

    #[cfg(feature = "ccm_as")]
    #[strum(serialize = "ccm_as")]
    CcmAs,
}
