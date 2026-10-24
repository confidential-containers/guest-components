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

use anyhow::{bail, Context, Result};

use super::CdhConfig;

/// Historical keyprovider name embedded in encrypted image annotations
/// (`org.opencontainers.image.enc.keys.provider.attestation-agent`).
const OCICRYPT_KEYPROVIDER_NAME: &str = "attestation-agent";

/// Environment variable consumed by `ocicrypt-rs` to locate the keyprovider
/// config file. See <https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md>.
pub const OCICRYPT_KEYPROVIDER_CONFIG_ENV: &str = "OCICRYPT_KEYPROVIDER_CONFIG";

impl CdhConfig {
    /// Ensure `ocicrypt-rs` is wired up to unwrap image encryption keys via
    /// CDH's KeyProvider service.
    ///
    /// * If `OCICRYPT_KEYPROVIDER_CONFIG` is unset, encrypted image support is
    ///   unavailable and we only warn about it.
    /// * If it is set but the file it points to does not exist, we write a
    ///   default config that points `ocicrypt-rs` at this CDH instance's
    ///   socket.
    /// * If it is set and the file exists, we only check that the socket it
    ///   points at matches `self.socket`, erroring out otherwise, since a
    ///   stale keyprovider config would silently break image decryption.
    pub(super) fn ensure_ocicrypt_keyprovider_config(&self) -> Result<()> {
        let Ok(path) = env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV) else {
            tracing::warn!(
                "{OCICRYPT_KEYPROVIDER_CONFIG_ENV} is not set; encrypted container images are not supported"
            );
            return Ok(());
        };
        self.ensure_ocicrypt_keyprovider_config_at(Path::new(&path))
    }

    /// Same as [`Self::ensure_ocicrypt_keyprovider_config`], but takes the
    /// configured path directly instead of reading it from the environment,
    /// so it can be exercised in tests without touching process-global state.
    fn ensure_ocicrypt_keyprovider_config_at(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(path, self.default_ocicrypt_keyprovider_config()).with_context(|| {
                format!(
                    "failed to write default ocicrypt keyprovider config to {}",
                    path.display()
                )
            })?;
            tracing::info!(
                path = %path.display(),
                socket = %self.socket,
                "wrote default ocicrypt keyprovider config pointing at CDH"
            );
            return Ok(());
        }

        let configured_socket = self.configured_ocicrypt_socket(path)?;
        if configured_socket != self.socket {
            bail!(
                "{OCICRYPT_KEYPROVIDER_CONFIG_ENV} at {} points ocicrypt-rs at socket \
                 '{configured_socket}', which does not match this CDH instance's socket '{}'",
                path.display(),
                self.socket,
            );
        }
        Ok(())
    }

    /// Read the socket that the ocicrypt keyprovider config at `path` points
    /// the `attestation-agent` provider at.
    fn configured_ocicrypt_socket(&self, path: &Path) -> Result<String> {
        let content = fs::read_to_string(path).with_context(|| {
            format!(
                "failed to read ocicrypt keyprovider config {}",
                path.display()
            )
        })?;
        let parsed: serde_json::Value = serde_json::from_str(&content).with_context(|| {
            format!(
                "failed to parse ocicrypt keyprovider config {}",
                path.display()
            )
        })?;
        let provider = &parsed["key-providers"][OCICRYPT_KEYPROVIDER_NAME];
        let socket = provider["ttrpc"].as_str().or(provider["grpc"].as_str());
        socket
            .with_context(|| {
                format!(
                    "ocicrypt keyprovider config {} has no ttrpc/grpc socket for provider '{OCICRYPT_KEYPROVIDER_NAME}'",
                    path.display()
                )
            })
            .map(str::to_string)
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
    use image_rs::config::ImageConfig;

    use crate::{AaConfig, CdhConfig, KbsConfig, LogConfig};

    fn test_config(socket: &str) -> CdhConfig {
        CdhConfig {
            log: LogConfig::default(),
            aa: AaConfig::default(),
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
    fn writes_config_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ocicrypt_config.json");

        let config = test_config("unix:///run/confidential-containers/cdh.sock");
        config.ensure_ocicrypt_keyprovider_config_at(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("attestation-agent"));
        assert!(content.contains(&config.socket));
    }

    #[test]
    fn accepts_existing_config_matching_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ocicrypt_config.json");
        let config = test_config("unix:///tmp/matching.sock");
        std::fs::write(&path, config.default_ocicrypt_keyprovider_config()).unwrap();

        config.ensure_ocicrypt_keyprovider_config_at(&path).unwrap();
    }

    #[test]
    fn errors_on_existing_config_with_mismatched_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ocicrypt_config.json");
        let written = test_config("unix:///tmp/other.sock");
        std::fs::write(&path, written.default_ocicrypt_keyprovider_config()).unwrap();

        let config = test_config("unix:///tmp/self.sock");
        assert!(config.ensure_ocicrypt_keyprovider_config_at(&path).is_err());
    }
}
