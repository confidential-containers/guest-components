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

// Set when the config file omits services_dir. A launcher that does not own
// the rest of the config (kbc still comes from the kernel command line, or
// from an initdata file) cannot add this one field: a file without kbc fails
// to load. An explicit services_dir in the config is left unchanged.
const CDH_SERVICES_DIR: &str = "CDH_SERVICES_DIR";

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

    if config.services_dir.is_none() {
        if let Ok(dir) = env::var(CDH_SERVICES_DIR) {
            if !dir.is_empty() {
                info!("Read per-service socket directory from env: {dir}");
                config.services_dir = Some(dir);
            }
        }
    }

    config.extend_credentials_from_kernel_cmdline()?;

    Ok((config, config_log))
}

#[cfg(test)]
mod tests {
    use std::{env, io::Write};

    use serial_test::serial;

    use crate::config::read_config;

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

        // services_dir from the environment fills the field only when the file
        // omits it.
        env::remove_var("CDH_SERVICES_DIR");
        let (config, _) = read_config(Some(config_path.clone())).unwrap();
        assert_eq!(config.services_dir, None);

        env::set_var("CDH_SERVICES_DIR", "/run/guest-services");
        let (config, _) = read_config(Some(config_path.clone())).unwrap();
        assert_eq!(config.services_dir.as_deref(), Some("/run/guest-services"));
        env::set_var("CDH_SERVICES_DIR", "");
        let (config, _) = read_config(Some(config_path.clone())).unwrap();
        assert_eq!(config.services_dir, None);
        env::remove_var("CDH_SERVICES_DIR");

        // no env again
        let (config, _) = read_config(Some(config_path)).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );
    }

    #[test]
    #[serial]
    fn test_config_services_dir_in_file_is_kept() {
        let config = r#"
services_dir = "/from-file"

[kbc]
name = "offline_fs_kbc"
        "#;
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        env::set_var("CDH_SERVICES_DIR", "/from-env");
        let (config, _) = read_config(Some(file.path().to_str().unwrap().to_string())).unwrap();
        assert_eq!(config.services_dir.as_deref(), Some("/from-file"));
        env::remove_var("CDH_SERVICES_DIR");
    }
}
