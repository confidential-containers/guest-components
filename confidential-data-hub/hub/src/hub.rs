// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

/// Base directory for CDH runtime data.
pub(crate) const CDH_BASE_DIR: &str = "/run/confidential-containers/cdh";

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use kms::{Annotations, ProviderSettings};
use tokio::sync::{Mutex, OnceCell};
use tracing::{debug, info, warn};

#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, RuntimeMeasurementResult,
};
#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;

use crate::storage::volume_type::Storage;
use crate::{image, secret, CdhConfig, DataHub, Error, Result};

pub struct Hub {
    #[allow(dead_code)]
    pub(crate) credentials: HashMap<String, String>,
    image_client: OnceCell<Mutex<ImageClient>>,
    #[cfg(feature = "ttrpc")]
    aa_client: OnceCell<Option<AttestationAgentServiceClient>>,
    config: CdhConfig,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        config.set_configuration_envs();
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();

        let mut hub = Self {
            credentials,
            config,
            image_client: OnceCell::const_new(),
            #[cfg(feature = "ttrpc")]
            aa_client: OnceCell::const_new(),
        };

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        info!("unseal secret called");

        let res = secret::unseal_secret(&secret).await?;

        Ok(res)
    }

    async fn unwrap_key(&self, annotation_packet: &[u8]) -> Result<Vec<u8>> {
        info!("unwrap key called");

        let lek = image::unwrap_key(annotation_packet).await?;
        Ok(lek)
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        info!("get resource called: {uri}");
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::KbsClient { source: e })?;

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &Annotations::default())
            .await
            .map_err(|e| Error::GetResource { source: e })?;
        Ok(res)
    }

    async fn secure_mount(&self, storage: Storage) -> Result<String> {
        info!("secure mount called");
        let res = storage.mount().await?;
        Ok(res)
    }

    async fn pull_image(&self, image_url: &str, bundle_path: &str) -> Result<String> {
        let client = self
            .image_client
            .get_or_try_init(
                || async move { initialize_image_client(self.config.image.clone()).await },
            )
            .await?;

        let image_info = client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await?;

        #[cfg(not(feature = "ttrpc"))]
        warn!(
            "`ttrpc` feature is not enabled, so all runtime measurement extension will be skipped."
        );

        #[cfg(feature = "ttrpc")]
        {
            use anyhow::anyhow;
            use ttrpc::context::with_timeout;

            // 10 seconds in nanoseconds
            const EXTEND_RUNTIME_MEASUREMENT_TIMEOUT: i64 = 10 * 1000 * 1000 * 1000;

            let aa_client = self
                .aa_client
                .get_or_try_init(|| async move { initialize_aa_client().await })
                .await?;

            let Some(aa_client) = aa_client else {
                warn!("Attestation Agent socket file not found, so all runtime measurement extension will be skipped.");
                return Ok(image_info.manifest_digest);
            };

            info!("Extend image pull event via AA's runtime measurement API...");
            debug!("The pulled image information: {image_info:?}");
            // The event follows definition in
            // https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md#confidential-containers-event-spec
            let req = ExtendRuntimeMeasurementRequest {
                Domain: "github.com/confidential-containers".to_string(),
                Operation: "PullImage".to_string(),
                Content: format!(
                    r#"{{"image":"{image_url}", "digest":"{}"}}"#,
                    image_info.manifest_digest
                ),
                ..Default::default()
            };
            let res = aa_client
                .extend_runtime_measurement(with_timeout(EXTEND_RUNTIME_MEASUREMENT_TIMEOUT), &req)
                .await
                .map_err(|e| Error::AttestationAgentClientError {
                    source: anyhow!("failed to extend runtime measurement: {e:?}"),
                })?;

            match res
                .Result
                .enum_value()
                .map_err(|e| Error::AttestationAgentClientError {
                    source: anyhow!("failed to get runtime measurement result: {e:?}"),
                })? {
                RuntimeMeasurementResult::OK => {
                    info!("image pull event extended runtime measurement successfully");
                }
                RuntimeMeasurementResult::NOT_SUPPORTED => {
                    warn!("Current platform does not support runtime measurement, skipping runtime measurement extension.")
                }
                RuntimeMeasurementResult::NOT_ENABLED => {
                    warn!("Runtime measurement is not enabled in Attestation Agent configuration, skipping runtime measurement extension.")
                }
            }
        }

        Ok(image_info.manifest_digest)
    }
}

async fn initialize_image_client(config: ImageConfig) -> Result<Mutex<ImageClient>> {
    debug!("Image client lazy initializing...");

    let image_client = Into::<ClientBuilder>::into(config).build().await?;

    Ok(Mutex::new(image_client))
}

#[cfg(feature = "ttrpc")]
async fn initialize_aa_client() -> Result<Option<AttestationAgentServiceClient>> {
    use anyhow::anyhow;

    const AA_SOCKET_FILE: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

    if !Path::new(AA_SOCKET_FILE).exists() {
        return Ok(None);
    }

    let c = ttrpc::r#async::Client::connect(AA_SOCKET_FILE)
        .await
        .map_err(|e| Error::AttestationAgentClientError {
            source: anyhow!("failed to connect to attestation agent: {e:?}"),
        })?;
    let client = AttestationAgentServiceClient::new(c);
    Ok(Some(client))
}
