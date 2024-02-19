use log::debug;
use serde::Deserialize;
use std::env;
use std::path::Path;
use std::sync::OnceLock;
use thiserror::Error;
use tokio::fs;

const PEER_POD_CONFIG_PATH: &str = "/run/peerpod/daemon.json";
static KATA_AGENT_CONFIG_PATH: OnceLock<String> = OnceLock::new();

#[derive(Error, Debug)]
pub enum ParamError {
    #[error("illegal aa_kbc_params format: {0}")]
    IllegalFormat(String),
    #[error("unable to read `aa_kbc_params` entry from kata-agent config file")]
    AgentConfigParsing(#[from] toml::de::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no `agent.aa_kbc_params` provided in kernel commandline")]
    MissingInCmdline,
}

pub struct AaKbcParams {
    kbc: String,
    uri: String,
}

impl AaKbcParams {
    pub fn kbc(&self) -> &str {
        &self.kbc
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}

impl TryFrom<String> for AaKbcParams {
    type Error = ParamError;

    fn try_from(value: String) -> Result<Self, ParamError> {
        let segments: Vec<&str> = value.split("::").collect();

        if segments.len() != 2 {
            return Err(ParamError::IllegalFormat(value));
        }

        let params = AaKbcParams {
            kbc: segments[0].into(),
            uri: segments[1].into(),
        };

        Ok(params)
    }
}

async fn get_value() -> Result<String, ParamError> {
    // first check whether we are in a peer pod
    if Path::new(PEER_POD_CONFIG_PATH).exists() {
        return from_config_file().await;
    }
    // finally use the kernel cmdline
    from_cmdline().await
}

pub async fn get_params() -> Result<AaKbcParams, ParamError> {
    let value = get_value().await?;
    value.try_into()
}

// We only care about the aa_kbc_params value at the moment
#[derive(Debug, Deserialize)]
struct AgentConfig {
    aa_kbc_params: String,
}

async fn from_config_file() -> Result<String, ParamError> {
    debug!("get aa_kbc_params from file");

    // check env for KATA_AGENT_CONFIG_PATH, fall back to default path
    let path: &String = KATA_AGENT_CONFIG_PATH.get_or_init(|| {
        env::var("KATA_AGENT_CONFIG_PATH").unwrap_or_else(|_| "/etc/agent-config.toml".into())
    });

    debug!("reading agent config from {}", path);
    let agent_config_str = std::fs::read_to_string(path)?;

    let agent_config: AgentConfig = toml::from_str(&agent_config_str)?;

    Ok(agent_config.aa_kbc_params)
}

async fn from_cmdline() -> Result<String, ParamError> {
    debug!("get aa_kbc_params from kernel cmdline");
    let cmdline = fs::read_to_string("/proc/cmdline").await?;
    let value = cmdline
        .split_ascii_whitespace()
        .find(|para| para.starts_with("agent.aa_kbc_params="))
        .ok_or(ParamError::MissingInCmdline)?
        .strip_prefix("agent.aa_kbc_params=")
        .expect("must have a prefix");
    Ok(value.into())
}
