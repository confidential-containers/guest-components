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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    // Unknown, empty, and wrong-case strings must all be rejected regardless
    // of which token features are compiled in. strum is case-sensitive by default.
    #[rstest]
    #[case("unknown_type")]
    #[case("")]
    #[case("KBS")]  // wrong case
    fn test_invalid_token_type_rejected(#[case] s: &str) {
        assert!(TokenType::from_str(s).is_err());
    }
}
