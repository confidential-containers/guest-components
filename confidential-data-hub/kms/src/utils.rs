// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Error, Result};

#[cfg(any(feature = "kbs", feature = "sev"))]
pub(crate) async fn get_kbs_host_from_cmdline() -> Result<String> {
    use tokio::fs;
    let cmdline = fs::read_to_string("/proc/cmdline")
        .await
        .map_err(|e| Error::GetKbsHost(format!("read kernel cmdline failed: {e}")))?;
    let kbs_host = cmdline
        .split_ascii_whitespace()
        .find(|para| para.starts_with("agent.aa_kbc_params="))
        .ok_or(Error::GetKbsHost(
            "no `agent.aa_kbc_params` provided in kernel commandline!".into(),
        ))?
        .split("::")
        .last()
        .ok_or(Error::GetKbsHost(
            "illegal input `agent.aa_kbc_params` format".into(),
        ))?
        .to_string();

    Ok(kbs_host)
}
