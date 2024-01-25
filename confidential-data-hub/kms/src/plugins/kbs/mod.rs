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
use attestation_agent::config::aa_kbc_params;
use lazy_static::lazy_static;
pub use resource_uri::ResourceUri;
use tokio::sync::Mutex;

use crate::{Annotations, Error, Getter, Result};

enum RealClient {
    #[cfg(feature = "kbs")]
    Cc(cc_kbc::CcKbc),
    #[cfg(feature = "sev")]
    Sev(sev::OnlineSevKbc),
    OfflineFs(offline_fs::OfflineFsKbc),
}

impl RealClient {
    async fn new() -> Result<Self> {
        let params = aa_kbc_params::get_params().await?;

        let c = match params.kbc() {
            #[cfg(feature = "kbs")]
            "cc_kbc" => RealClient::Cc(cc_kbc::CcKbc::new(params.uri()).await?),
            #[cfg(feature = "sev")]
            "online_sev_kbc" => RealClient::Sev(sev::OnlineSevKbc::new(params.uri()).await?),
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
