use std::env;
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug)]
pub enum ParamError {
    #[error("illegal aa_kbc_params format: {0}")]
    IllegalFormat(String),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no `agent.aa_kbc_params` provided in kernel commandline")]
    MissingInCmdline,
}

pub struct AaKbcParams {
    pub kbc: String,
    pub uri: String,
}

impl Default for AaKbcParams {
    fn default() -> Self {
        Self {
            kbc: "offline_fs_kbc".into(),
            uri: "".into(),
        }
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

impl AaKbcParams {
    fn get_value() -> Result<String, ParamError> {
        // first check env
        if let Ok(params) = env::var("AA_KBC_PARAMS") {
            debug!("get aa_kbc_params from env.");
            return Ok(params);
        }

        // finally use the kernel cmdline
        Self::from_cmdline()
    }

    pub fn new() -> Result<Self, ParamError> {
        let Ok(value) = Self::get_value() else {
            debug!("failed to get aa_kbc_params in either both env or kernel cmdline, use `offline_fs_kbc::null` as default.");
            return Ok(Self::default());
        };

        value.try_into()
    }

    fn from_cmdline() -> Result<String, ParamError> {
        debug!("get aa_kbc_params from kernel cmdline");
        let cmdline = std::fs::read_to_string("/proc/cmdline")?;
        let value = cmdline
            .split_ascii_whitespace()
            .find(|para| para.starts_with("agent.aa_kbc_params="))
            .ok_or(ParamError::MissingInCmdline)?
            .strip_prefix("agent.aa_kbc_params=")
            .expect("must have a prefix");
        Ok(value.into())
    }
}
