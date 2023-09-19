// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Context, Result};
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use serde::{Deserialize, Serialize};
use tokio::fs;

const PEER_POD_CONFIG_PATH: &str = "/peerpod/daemon.json";

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

pub(crate) async fn get_kbs_token() -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

    // Check for /peerpod/daemon.json to see if we are in a peer pod
    // If so we need to read from the agent-config file, not /proc/cmdline
    let kbs_host_addr = match Path::new(PEER_POD_CONFIG_PATH).exists() {
        true => get_kbs_host_from_config_file().await?,
        false => get_kbs_host_from_cmdline().await?,
    };

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

pub(crate) async fn get_kbs_host_from_config_file() -> Result<String> {
    // We only care about the aa_kbc_params value at the moment
    #[derive(Debug, Deserialize)]
    struct AgentConfig {
        aa_kbc_params: Option<String>,
    }

    // Hard-code agent config path to "/etc/agent-config.toml" as a workaround
    let agent_config_str = fs::read_to_string("/etc/agent-config.toml")
        .context("Failed to read /etc/agent-config.toml file")?;

    let agent_config: AgentConfig = toml::from_str(&agent_config_str)
        .context("Failed to deserialize /etc/agent-config.toml")?;

    agent_config.aa_kbc_params.ok_or(anyhow!(
        "no `aa_kbc_params` found in /etc/agent-config.toml!",
    ))
}
