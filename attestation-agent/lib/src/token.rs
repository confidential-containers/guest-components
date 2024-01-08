// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Context, Result};
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use log::debug;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use std::sync::OnceLock;
use tokio::fs;

const PEER_POD_CONFIG_PATH: &str = "/run/peerpod/daemon.json";

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

static KATA_AGENT_CONFIG_PATH: OnceLock<String> = OnceLock::new();

pub(crate) async fn get_kbs_token() -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

    // Check for /run/peerpod/daemon.json to see if we are in a peer pod
    // If so we need to read from the agent-config file, not /proc/cmdline
    let kbc_params = match Path::new(PEER_POD_CONFIG_PATH).exists() {
        true => get_kbc_params_from_config_file().await?,
        false => get_kbc_params_from_cmdline().await?,
    };

    let kbs_host_url = extract_kbs_host_url(&kbc_params)?;

    let mut client =
        KbsClientBuilder::with_evidence_provider(evidence_provider, &kbs_host_url).build()?;

    let (token, tee_keypair) = client.get_token().await?;
    let message = Message {
        token: token.content,
        tee_keypair: tee_keypair.to_pkcs1_pem()?.to_string(),
    };

    let res = serde_json::to_vec(&message)?;
    Ok(res)
}

fn extract_kbs_host_url(kbc_params: &str) -> Result<String> {
    let kbs_host = kbc_params
        .split("::")
        .last()
        .ok_or(anyhow!("illegal input `agent.aa_kbc_params` format",))?
        .to_string();

    Ok(kbs_host)
}

pub(crate) async fn get_kbc_params_from_cmdline() -> Result<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").await?;
    let kbc_params = cmdline
        .split_ascii_whitespace()
        .find(|para| para.starts_with("agent.aa_kbc_params="))
        .ok_or(anyhow!(
            "no `agent.aa_kbc_params` provided in kernel commandline!",
        ))?
        .strip_prefix("agent.aa_kbc_params=")
        .expect("must have one")
        .to_string();
    Ok(kbc_params)
}

pub(crate) async fn get_kbc_params_from_config_file() -> Result<String> {
    // We only care about the aa_kbc_params value at the moment
    #[derive(Debug, Deserialize)]
    struct AgentConfig {
        aa_kbc_params: Option<String>,
    }

    // check env for KATA_AGENT_CONFIG_PATH, fall back to default path
    let path: &String = KATA_AGENT_CONFIG_PATH.get_or_init(|| {
        env::var("KATA_AGENT_CONFIG_PATH").unwrap_or_else(|_| "/etc/agent-config.toml".into())
    });

    debug!("reading agent config from {}", path);
    let agent_config_str = fs::read_to_string(path)
        .await
        .context(format!("Failed to read {path}"))?;

    let agent_config: AgentConfig =
        toml::from_str(&agent_config_str).context(format!("Failed to deserialize {path}"))?;

    agent_config
        .aa_kbc_params
        .ok_or(anyhow!("no `aa_kbc_params` found in {path}!"))
}
