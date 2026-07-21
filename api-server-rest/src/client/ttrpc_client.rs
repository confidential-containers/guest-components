// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use tokio::sync::RwLock;

pub struct CachedTtrpcClient<C> {
    client: RwLock<Option<C>>,
    addr: String,
    name: &'static str,
    new_client: fn(ttrpc::asynchronous::Client) -> C,
}

impl<C> CachedTtrpcClient<C>
where
    C: Clone,
{
    pub async fn new(
        addr: &str,
        name: &'static str,
        new_client: fn(ttrpc::asynchronous::Client) -> C,
    ) -> Result<Self> {
        let this = Self {
            client: RwLock::new(None),
            addr: addr.to_string(),
            name,
            new_client,
        };

        Ok(this)
    }

    async fn connect_client(&self) -> Result<C> {
        let inner = ttrpc::asynchronous::Client::connect(&self.addr)
            .await
            .with_context(|| {
                format!("ttrpc connect to {} addr: {} failed", self.name, self.addr)
            })?;

        Ok((self.new_client)(inner))
    }

    pub async fn ensure_client(&self) -> Result<C> {
        {
            let client_guard = self.client.read().await;
            if let Some(client) = client_guard.as_ref() {
                return Ok(client.clone());
            }
        }

        let mut client_guard = self.client.write().await;
        if client_guard.is_none() {
            let client = self.connect_client().await?;
            *client_guard = Some(client);
        }

        client_guard
            .as_ref()
            .cloned()
            .with_context(|| format!("{} ttrpc client is not initialized", self.name))
    }

    pub async fn call_with_retry<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: Fn(C) -> Fut,
        Fut: std::future::Future<Output = ttrpc::Result<T>>,
    {
        let client = self.ensure_client().await?;

        match f(client).await {
            std::result::Result::Ok(res) => std::result::Result::Ok(res),

            std::result::Result::Err(ttrpc::Error::LocalClosed) => {
                *self.client.write().await = None;

                let client = self.ensure_client().await.with_context(|| {
                    format!("failed to reconnect to {} after LocalClosed", self.name)
                })?;

                f(client)
                    .await
                    .context("ttrpc request error after reconnect")
            }

            std::result::Result::Err(e) => {
                std::result::Result::Err(e).context("ttrpc request error")
            }
        }
    }
}
