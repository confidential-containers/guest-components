// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Abstraction for KBCs as a KMS plugin.

#[cfg(feature = "kbs")]
mod cc_kbc;

#[cfg(feature = "sev")]
mod sev;

mod offline_fs;

use std::sync::Arc;

use async_trait::async_trait;
use lazy_static::lazy_static;
pub use resource_uri::ResourceUri;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use tokio::sync::Mutex;

use crate::{Annotations, Error, Getter, Result};

const PEER_POD_CONFIG_PATH: &str = "/peerpod/daemon.json";

enum RealClient {
    #[cfg(feature = "kbs")]
    Cc(cc_kbc::CcKbc),
    #[cfg(feature = "sev")]
    Sev(sev::OnlineSevKbc),
    OfflineFs(offline_fs::OfflineFsKbc),
}

impl RealClient {
    async fn new() -> Result<Self> {
        // Check for /peerpod/daemon.json to see if we are in a peer pod
        // If so we need to read from the agent-config file, not /proc/cmdline
        let (kbc, _kbs_host) = match Path::new(PEER_POD_CONFIG_PATH).exists() {
            true => get_aa_params_from_config_file().await?,
            false => get_aa_params_from_cmdline().await?,
        };

        let c = match &kbc[..] {
            #[cfg(feature = "kbs")]
            "cc_kbc" => RealClient::Cc(cc_kbc::CcKbc::new(&_kbs_host).await?),
            #[cfg(feature = "sev")]
            "online_sev_kbc" => RealClient::Sev(sev::OnlineSevKbc::new(&_kbs_host).await?),
            "offline_fs_kbc" => RealClient::OfflineFs(offline_fs::OfflineFsKbc::new().await?),
            others => return Err(Error::KbsClientError(format!("unknown kbc name {others}, only support `cc_kbc`(feature `kbs`), `online_sev_kbc` (feature `sev`) and `offline_fs_kbc`."))),
        };

        Ok(c)
    }
}

lazy_static! {
    static ref KBS_CLIENT: Arc<Mutex<Option<RealClient>>> = Arc::new(Mutex::new(None));
}

#[async_trait]
pub trait Kbc: Send + Sync {
    async fn get_resource(&mut self, _rid: ResourceUri) -> Result<Vec<u8>>;
}

/// A fake KbcClient to carry the [`Getter`] semantics. The real `new()`
/// and `get_resource()` will happen to the static variable [`KBS_CLIENT`].
///
/// Why we use a static variable here is the initialization of kbc is not
/// idempotent. For example online-sev-kbc will delete a file on local
/// filesystem, so we should try to reuse the online-sev-kbc created at the
/// first time.
pub struct KbcClient;

#[async_trait]
impl Getter for KbcClient {
    async fn get_secret(&mut self, name: &str, _annotations: &Annotations) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::try_from(name)
            .map_err(|_| Error::KbsClientError(format!("illegal kbs resource uri: {name}")))?;
        let real_client = KBS_CLIENT.clone();
        let mut client = real_client.lock().await;

        if client.is_none() {
            let c = RealClient::new().await?;
            *client = Some(c);
        }

        let client = client.as_mut().expect("must be initialized");

        match client {
            #[cfg(feature = "kbs")]
            RealClient::Cc(c) => c.get_resource(resource_uri).await,
            #[cfg(feature = "sev")]
            RealClient::Sev(c) => c.get_resource(resource_uri).await,
            RealClient::OfflineFs(c) => c.get_resource(resource_uri).await,
        }
    }
}

impl KbcClient {
    pub async fn new() -> Result<Self> {
        let client = KBS_CLIENT.clone();
        let mut client = client.lock().await;
        if client.is_none() {
            let c = RealClient::new().await?;
            *client = Some(c);
        }

        Ok(KbcClient {})
    }
}

async fn get_aa_params_from_cmdline() -> Result<(String, String)> {
    use tokio::fs;
    let cmdline = fs::read_to_string("/proc/cmdline")
        .await
        .map_err(|e| Error::KbsClientError(format!("read kernel cmdline failed: {e}")))?;
    let aa_kbc_params = cmdline
        .split_ascii_whitespace()
        .find(|para| para.starts_with("agent.aa_kbc_params="))
        .ok_or(Error::KbsClientError(
            "no `agent.aa_kbc_params` provided in kernel commandline!".into(),
        ))?
        .strip_prefix("agent.aa_kbc_params=")
        .expect("must have a prefix")
        .split("::")
        .collect::<Vec<&str>>();

    if aa_kbc_params.len() != 2 {
        return Err(Error::KbsClientError(
            "Illegal `agent.aa_kbc_params` format provided in kernel commandline.".to_string(),
        ));
    }

    Ok((aa_kbc_params[0].to_string(), aa_kbc_params[1].to_string()))
}

async fn get_aa_params_from_config_file() -> Result<(String, String)> {
    // We only care about the aa_kbc_params value at the moment
    #[derive(Debug, Deserialize)]
    struct AgentConfig {
        aa_kbc_params: Option<String>,
    }

    // Hard-code agent config path to "/etc/agent-config.toml" as a workaround
    let agent_config_str = fs::read_to_string("/etc/agent-config.toml").map_err(|e| {
        Error::KbsClientError(format!("Failed to read /etc/agent-config.toml file: {e}"))
    })?;

    let agent_config: AgentConfig = toml::from_str(&agent_config_str).map_err(|e| {
        Error::KbsClientError(format!("Failed to deserialize /etc/agent-config.toml: {e}"))
    })?;

    let aa_kbc_params = agent_config.aa_kbc_params.ok_or(Error::KbsClientError(
        "no `aa_kbc_params` found in /etc/agent-config.toml".into(),
    ))?;

    let aa_kbc_params_vec = aa_kbc_params.split("::").collect::<Vec<&str>>();

    if aa_kbc_params_vec.len() != 2 {
        return Err(Error::KbsClientError(
            "Illegal `aa_kbc_params` format provided in /etc/agent-config.toml.".to_string(),
        ));
    }

    Ok((
        aa_kbc_params_vec[0].to_string(),
        aa_kbc_params_vec[1].to_string(),
    ))
}
