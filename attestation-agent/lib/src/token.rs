// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use serde::Serialize;
use tokio::fs;

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

pub(crate) async fn get_kbs_token() -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let kbs_host_addr = get_kbs_host_from_cmdline().await?;
    let mut client =
        KbsClientBuilder::with_evidence_provider(evidence_provider, &kbs_host_addr).build()?;

    let (token, tee_keypair) = client.get_token().await?;
    let message = Message {
        token: token.content,
        tee_keypair: tee_keypair.to_pkcs1_pem()?.to_string(),
    };

    let res = serde_json::to_vec(&message)?;
    Ok(res)
}

pub(crate) async fn get_kbs_host_from_cmdline() -> Result<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").await?;
    let kbs_host = cmdline
        .split_ascii_whitespace()
        .find(|para| para.starts_with("agent.aa_kbc_params="))
        .ok_or(anyhow!(
            "no `agent.aa_kbc_params` provided in kernel commandline!",
        ))?
        .strip_prefix("agent.aa_kbc_params=")
        .expect("must have one")
        .split("::")
        .last()
        .ok_or(anyhow!("illegal input `agent.aa_kbc_params` format",))?
        .to_string();

    Ok(kbs_host)
}
