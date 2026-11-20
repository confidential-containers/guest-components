// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Context;
use async_trait::async_trait;
use resource_uri::ResourceUri;
use thiserror::Error;
use tracing::debug;
use zeroize::Zeroizing;

use crate::{hub::Hub, DataHub};

pub type Result<T> = std::result::Result<T, KeyProviderError>;

#[derive(Error, Debug)]
pub enum KeyProviderError {
    #[error("failed to unseal secret: {source}")]
    UnsealSecret {
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to get resource: {source}")]
    GetResource {
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to read file: {source}")]
    FileRead {
        #[source]
        source: std::io::Error,
    },
    #[error("illegal key scheme: {0}")]
    IllegalKeyScheme(String),

    #[error("key provider not configured")]
    KeyProviderNotConfigured,
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn unseal_secret(&self, secret: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_resource(&self, uri: &str) -> anyhow::Result<Vec<u8>>;
}

/// Now the only one entity to handle both secret unsealing and resource getting is
/// the `Hub` itself. This implementation would help us to deliver the global object
/// `Hub` to concerete function call.
#[async_trait]
impl KeyProvider for Hub {
    async fn unseal_secret(&self, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
        DataHub::unseal_secret(self, secret.to_vec())
            .await
            .context("key provider unseal secret failed")
    }
    async fn get_resource(&self, uri: &str) -> anyhow::Result<Vec<u8>> {
        DataHub::get_resource(self, uri.to_string())
            .await
            .context("key provider get resource failed")
    }
}

/// Get the key based on the key uri. Now we supports the following key uri types:
/// - `sealed.*`: Unseal the secret from the key provider.
/// - `kbs:///uri`: Get the key using kbc client (kbs or offline_fs_kbc).
/// - `file://path`: Get the key from the local path.
///
/// Note that the parameter key_provider is optional. If it is not provided,
/// neither sealed secret nor kbs key can be used.
pub async fn get_plaintext_key(
    key_uri: &str,
    key_provider: Option<&dyn KeyProvider>,
) -> Result<Zeroizing<Vec<u8>>> {
    let ensure_key_provider =
        || key_provider.ok_or_else(|| KeyProviderError::KeyProviderNotConfigured);
    let key = if key_uri.starts_with("sealed.") {
        debug!("get key with sealed secret");
        ensure_key_provider()?
            .unseal_secret(key_uri.as_bytes())
            .await
            .map_err(|source| KeyProviderError::UnsealSecret { source })?
    } else if ResourceUri::try_from(key_uri).is_ok() {
        debug!("get key from kbs");
        ensure_key_provider()?
            .get_resource(key_uri)
            .await
            .map_err(|source| KeyProviderError::GetResource { source })?
    } else if key_uri.starts_with("file://") {
        debug!("get key from local path");
        let path = key_uri.trim_start_matches("file://");
        tokio::fs::read(path)
            .await
            .map_err(|source| KeyProviderError::FileRead { source })?
    } else {
        return Err(KeyProviderError::IllegalKeyScheme(key_uri.to_string()));
    };

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use crate::keyprovider::{get_plaintext_key, KeyProvider};
    use async_trait::async_trait;

    #[tokio::test]
    async fn test_get_plaintext_key_via_key_provider() {
        struct MockKeyProvider;

        #[async_trait]
        impl KeyProvider for MockKeyProvider {
            async fn unseal_secret(&self, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
                assert_eq!(secret, b"sealed.mock-jws");
                Ok(b"unsealed-passphrase".to_vec())
            }

            async fn get_resource(&self, uri: &str) -> anyhow::Result<Vec<u8>> {
                assert_eq!(uri, "kbs:///default/luks/key");
                Ok(b"kbs-passphrase".to_vec())
            }
        }

        let provider = MockKeyProvider;
        let sealed_key = get_plaintext_key("sealed.mock-jws", Some(&provider))
            .await
            .unwrap();
        assert_eq!(&*sealed_key, b"unsealed-passphrase");

        let kbs_key = get_plaintext_key("kbs:///default/luks/key", Some(&provider))
            .await
            .unwrap();
        assert_eq!(&*kbs_key, b"kbs-passphrase");

        assert!(get_plaintext_key("kbs:///default/luks/key", None)
            .await
            .is_err());
    }
}
