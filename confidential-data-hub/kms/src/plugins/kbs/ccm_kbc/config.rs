// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use tracing::{debug, info, warn};

use crate::Result;

const ENV_ENDPOINT: &str = "CCM_KBC_DSM_ENDPOINT";
const ENV_APP_ID: &str = "CCM_KBC_APP_ID";

const CMDLINE_ENDPOINT: &str = "ccm.kbc_dsm_endpoint=";
const CMDLINE_APP_ID: &str = "ccm.kbc_app_id=";

const CMDLINE_PATH: &str = "/proc/cmdline";

pub(super) struct CcmKbcConfig {
    pub(super) dsm_endpoint: Option<String>,
    pub(super) dsm_app_id: Option<String>,
}

fn get_env_or_cmdline(env_var: &str, cmdline_prefix: &str) -> Option<String> {
    if let Ok(value) = env::var(env_var) {
        debug!("ccm_kbc: {env_var} loaded from env (len={})", value.len());
        return Some(value);
    }

    let cmdline = std::fs::read_to_string(CMDLINE_PATH).ok()?;
    let value = cmdline
        .split_ascii_whitespace()
        .find_map(|p| p.strip_prefix(cmdline_prefix).map(String::from))?;

    debug!(
        "ccm_kbc: {env_var} loaded from cmdline (len={})",
        value.len()
    );
    Some(value)
}

impl CcmKbcConfig {
    pub(super) fn from_env_or_cmdline() -> Result<Self> {
        let dsm_endpoint = get_env_or_cmdline(ENV_ENDPOINT, CMDLINE_ENDPOINT)
            .map(|e| e.trim_end_matches('/').to_string());
        let dsm_app_id = get_env_or_cmdline(ENV_APP_ID, CMDLINE_APP_ID);
        if dsm_app_id.is_none() {
            warn!("ccm_kbc: no DSM app id configured");
        }

        info!("ccm_kbc: config loaded (endpoint={dsm_endpoint:?}, app_id={dsm_app_id:?})");

        Ok(Self {
            dsm_endpoint,
            dsm_app_id,
        })
    }
}
