// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Error, Result};
use resource_uri::{ResourcePluginPath, ResourceUri};
use uuid::Uuid;

const EXPECTED_URI: &str = "kbs:///dsm/key/<uuid>";

pub(super) fn parse_dsm_uuid(rid: &ResourceUri) -> Result<Uuid> {
    let uri = rid.whole_uri();
    let bad = |detail: String| {
        Error::KbsClientError(format!(
            "ccm_kbc: invalid resource uri '{uri}': {detail}; expected {EXPECTED_URI}"
        ))
    };

    let path = ResourcePluginPath::try_from(rid.clone()).map_err(|e| bad(e.to_string()))?;

    if path.repo != "dsm" {
        return Err(bad(format!(
            "repository must be 'dsm', got '{}'",
            path.repo
        )));
    }

    if path.r#type != "key" {
        return Err(bad(format!("type must be 'key', got '{}'", path.r#type)));
    }

    Uuid::parse_str(&path.tag)
        .map_err(|e| bad(format!("tag '{}' is not a valid UUID: {e}", path.tag)))
}
