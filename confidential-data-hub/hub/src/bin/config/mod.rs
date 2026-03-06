// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::{Context, Result};
use confidential_data_hub::CdhConfig;
use tracing::info;

const CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS: &str =
    "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS";

pub fn read_config(config_path: Option<String>) -> Result<(CdhConfig, String)> {
    let (mut config, config_log) = match config_path {
        Some(config_path) => {
            let config = CdhConfig::from_file(&config_path[..])
                .with_context(|| format!("failed to read config file {config_path}"))?;
            let log = format!("Using config file: {config_path}");
            (config, log)
        }
        None => {
            let log = "No CDH config path specified. Using default configuration.".to_string();
            let config = CdhConfig::default_with_kernel_cmdline()
                .with_context(|| "failed to read default configuration".to_string())?;
            (config, log)
        }
    };

    if let std::result::Result::Ok(env) =
        env::var(CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS)
    {
        info!("Read authenticated registry credentials URI from env: {env}");
        config.image.authenticated_registry_credentials_uri = Some(env);
    }

    config.extend_credentials_from_kernel_cmdline()?;

    Ok((config, config_log))
}

#[cfg(test)]
mod tests {
    use std::{env, io::Write};

    use anyhow::anyhow;
    use confidential_data_hub::{CdhConfig, KbsConfig, LogConfig, DEFAULT_CDH_SOCKET_ADDR};
    use image_rs::config::ImageConfig;
    use serial_test::serial;

    use crate::config::read_config;

    #[test]
    #[serial]
    fn test_config_path() {
        // --config takes precedence,
        // then env.CDH_CONFIG_PATH

        let (config, _) = read_config(None).expect("Must be successful");
        let expected = CdhConfig {
            log: LogConfig::default(),
            kbc: KbsConfig {
                name: "offline_fs_kbc".into(),
                url: "".into(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            image: ImageConfig::from_kernel_cmdline(),
            skip_sealed_secret_verification: false,
        };
        assert_eq!(config, expected);

        let error = read_config(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("failed to read config file /thing");
        assert_eq!(format!("{error}"), format!("{expected}"));

        env::set_var("CDH_CONFIG_PATH", "/byenv");
        let error = read_config(None).unwrap_err();
        let expected = anyhow!("failed to read config file /byenv");
        assert_eq!(format!("{error}"), format!("{expected}"));
        env::remove_var("CDH_CONFIG_PATH");

        let error = read_config(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("failed to read config file /thing");
        assert_eq!(format!("{error}"), format!("{expected}"));
    }

    #[test]
    #[serial]
    fn test_config_auth_override_by_env() {
        let config = r#"
[kbc]
name = "offline_fs_kbc"

[image]
authenticated_registry_credentials_uri = "kbs:///default/auth/1"
        "#;
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();

        // without env and from config file
        let config_path = file.path().to_str().unwrap().to_string();
        let (config, _) = read_config(Some(config_path.clone())).expect("Must be successful");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );

        // overrided by env
        env::set_var(
            "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS",
            "file:///test",
        );
        let (config, _) = read_config(Some(config_path.clone())).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("file:///test".to_string())
        );
        env::remove_var("CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS");

        // no env again
        let (config, _) = read_config(Some(config_path)).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );
    }
}
