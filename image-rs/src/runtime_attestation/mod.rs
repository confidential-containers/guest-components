// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use log::{info, warn};
use std::result::Result::Ok;
use tokio::sync::{Mutex, OnceCell};

#[cfg(feature = "runtime-attestation-grpc")]
mod grpc;

#[cfg(feature = "runtime-attestation-ttrpc")]
mod ttrpc;

#[cfg(feature = "runtime-attestation-ttrpc")]
mod ttrpc_proto;

static RUNTIME_MEASUREMENT: OnceCell<Mutex<Option<RuntimeMeasurement>>> = OnceCell::const_new();

pub struct RuntimeMeasurement {
    client: Box<dyn Client>,
}

#[async_trait]
trait Client: Send + Sync {
    async fn extend_runtime_measurement(
        &mut self,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<()>;
}

impl RuntimeMeasurement {
    pub async fn new() -> Result<Self> {
        let client: Box<dyn Client> = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "runtime-attestation-ttrpc")] {
                    info!("runtime-attestation uses ttrpc");
                    Box::new(ttrpc::Ttrpc::new().context("ttrpc client init failed")?)
                } else if #[cfg(feature = "runtime-attestation-grpc")] {
                    info!("runtime-attestation uses grpc");
            Box::new(grpc::Grpc::new().await.context("grpc client init failed")?)
                } else {
                    compile_error!("`runtime-attestation-ttrpc` or `runtime-attestation-grpc` must be enabled.");
                }
            }
        };

        Ok(Self { client })
    }
}

async fn get_runtime_measurement() -> Mutex<Option<RuntimeMeasurement>> {
    match RuntimeMeasurement::new().await {
        Ok(runtime_measurement) => Mutex::new(Some(runtime_measurement)),
        Err(err) => {
            warn!("Failed to initialize runtime measurement: {:?}", err);
            Mutex::new(None)
        }
    }
}

pub async fn extend_runtime_measurement(
    domain: &str,
    operation: &str,
    content: &str,
) -> Result<()> {
    RUNTIME_MEASUREMENT
        .get_or_init(get_runtime_measurement)
        .await
        .lock()
        .await
        .as_mut()
        .ok_or_else(|| anyhow!("Uninitialized runtime measurement"))?
        .client
        .extend_runtime_measurement(domain, operation, content)
        .await
        .map_err(|e| anyhow!("Failed to extend runtime measurement: {:?}", e))?;

    Ok(())
}
