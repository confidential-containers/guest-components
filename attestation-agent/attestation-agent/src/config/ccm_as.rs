// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CcmAsConfig {
    /// Domain name(s) CCM issues the workload certificate for.
    pub ccm_domain_names: Vec<String>,

    /// Optional Fortanix AppConfig ID (hex-encoded).
    #[serde(default)]
    pub ccm_appconfig_id: Option<String>,
}
