// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Default ocicrypt keyprovider config generation.
//!
//! This module is only compiled when the `ttrpc` or `grpc` feature is enabled,
//! since the generated config points ocicrypt-rs at CDH's UnwrapKey RPC
//! service. Library-only builds (e.g. cdh-oneshot) have no such listener.

use std::{env, fs, path::Path};

use anyhow::{Context, Result};

use crate::hub::CDH_BASE_DIR;

use super::CdhConfig;

/// Historical keyprovider name embedded in encrypted image annotations
/// (`org.opencontainers.image.enc.keys.provider.attestation-agent`).
const OCICRYPT_KEYPROVIDER_NAME: &str = "attestation-agent";

/// Environment variable consumed by `ocicrypt-rs` to locate the keyprovider
/// config file. See <https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md>.
pub const OCICRYPT_KEYPROVIDER_CONFIG_ENV: &str = "OCICRYPT_KEYPROVIDER_CONFIG";

impl CdhConfig {
    /// Ensure `OCICRYPT_KEYPROVIDER_CONFIG` is set so `ocicrypt-rs` can unwrap
    /// image encryption keys via CDH's KeyProvider service.
    ///
    /// If the env var is already set (operator override), it is left alone.
    /// Otherwise a config file is generated that maps the historical
    /// `attestation-agent` provider name to this CDH instance's socket.
    pub(super) fn ensure_ocicrypt_keyprovider_config(&self) -> Result<()> {
        if env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV).is_ok() {
            return Ok(());
        }

        // In CoCo scenarios /run is a ramfs inside the guest, so it cannot be
        // tampered with by the host.
        let parent = Path::new(CDH_BASE_DIR);
        let path = parent.join("ocicrypt_config.json");
        let parent = path.parent().expect("path has a parent directory");
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        fs::write(&path, self.default_ocicrypt_keyprovider_config()).with_context(|| {
            format!(
                "failed to write default ocicrypt keyprovider config to {}",
                path.display()
            )
        })?;

        tracing::info!(
            path = %path.display(),
            socket = %self.socket,
            "OCICRYPT_KEYPROVIDER_CONFIG unset; wrote default keyprovider config pointing at CDH"
        );
        env::set_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV, path);
        Ok(())
    }

    /// Build the default ocicrypt keyprovider JSON for this CDH instance.
    fn default_ocicrypt_keyprovider_config(&self) -> String {
        cfg_if::cfg_if! {
            if #[cfg(feature = "ttrpc")] {
                // Prefer ttrpc when both RPC features are enabled (CoCo default).
                format!(
                    r#"{{"key-providers":{{"{name}":{{"ttrpc":"{socket}"}}}}}}"#,
                    name = OCICRYPT_KEYPROVIDER_NAME,
                    socket = self.socket,
                )
            } else {
                format!(
                    r#"{{"key-providers":{{"{name}":{{"grpc":"{socket}"}}}}}}"#,
                    name = OCICRYPT_KEYPROVIDER_NAME,
                    socket = self.socket,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use image_rs::config::ImageConfig;
    use serial_test::serial;

    use super::OCICRYPT_KEYPROVIDER_CONFIG_ENV;
    use crate::{CdhConfig, KbsConfig, LogConfig};

    fn test_config(socket: &str) -> CdhConfig {
        CdhConfig {
            log: LogConfig::default(),
            kbc: KbsConfig {
                name: "offline_fs_kbc".to_string(),
                url: "".to_string(),
                kbs_cert: None,
            },
            credentials: vec![],
            image: ImageConfig::default(),
            socket: socket.to_string(),
            skip_sealed_secret_verification: false,
        }
    }

    #[test]
    #[serial]
    fn default_ocicrypt_keyprovider_config_uses_socket() {
        let config = test_config("unix:///tmp/test-cdh.sock");

        let json = config.default_ocicrypt_keyprovider_config();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let provider = &parsed["key-providers"]["attestation-agent"];
        #[cfg(feature = "ttrpc")]
        assert_eq!(
            provider["ttrpc"].as_str().unwrap(),
            "unix:///tmp/test-cdh.sock"
        );
        #[cfg(all(feature = "grpc", not(feature = "ttrpc")))]
        assert_eq!(
            provider["grpc"].as_str().unwrap(),
            "unix:///tmp/test-cdh.sock"
        );
    }

    #[test]
    #[serial]
    fn set_configuration_envs_writes_ocicrypt_config_when_unset() {
        env::remove_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV);

        let config = test_config("unix:///run/confidential-containers/cdh.sock");
        config.set_configuration_envs().unwrap();

        let path = env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("attestation-agent"));
        assert!(content.contains(&config.socket));

        env::remove_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[serial]
    fn set_configuration_envs_preserves_existing_ocicrypt_config() {
        env::set_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV, "/already/set.json");

        let config = test_config("unix:///tmp/other.sock");
        config.set_configuration_envs().unwrap();
        assert_eq!(
            env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV).unwrap(),
            "/already/set.json"
        );

        env::remove_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV);
    }
}
