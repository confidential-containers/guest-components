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

#[derive(Debug)]
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
            debug!(
                "failed to get aa_kbc_params in either both env or kernel cmdline, use `offline_fs_kbc::null` as default."
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("offline_fs_kbc::http://127.0.0.1:8080", "offline_fs_kbc", "http://127.0.0.1:8080")]
    #[case("cc_kbc::https://kbs.example.com", "cc_kbc", "https://kbs.example.com")]
    #[case("null_kbc::", "null_kbc", "")]
    fn test_try_from_valid_params(
        #[case] input: &str,
        #[case] expected_kbc: &str,
        #[case] expected_uri: &str,
    ) {
        let params = AaKbcParams::try_from(input.to_string())
            .expect("should parse successfully");
        assert_eq!(params.kbc, expected_kbc);
        assert_eq!(params.uri, expected_uri);
    }

    #[rstest]
    #[case("no_separator_at_all")]
    #[case("one:colon")]
    #[case("a::b::c")]
    fn test_try_from_invalid_format_returns_error(#[case] input: &str) {
        let err = AaKbcParams::try_from(input.to_string())
            .expect_err("expected error for invalid input");
        assert!(matches!(err, ParamError::IllegalFormat(_)));
    }

    #[test]
    fn test_default_kbc_is_offline_fs() {
        let params = AaKbcParams::default();
        assert_eq!(params.kbc, "offline_fs_kbc");
        assert_eq!(params.uri, "");
    }

    // AaKbcParams::new() reads AA_KBC_PARAMS from env when present.
    // This covers the get_value() → env branch that TryFrom tests don't reach.
    #[test]
    fn test_new_reads_from_env() {
        std::env::set_var("AA_KBC_PARAMS", "cc_kbc::https://kbs.example.com");
        let params = AaKbcParams::new().expect("new() failed");
        std::env::remove_var("AA_KBC_PARAMS");
        assert_eq!(params.kbc, "cc_kbc");
        assert_eq!(params.uri, "https://kbs.example.com");
    }
}
