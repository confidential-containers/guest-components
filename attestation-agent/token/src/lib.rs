// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::Result;
use async_trait::async_trait;

#[cfg(feature = "kbs")]
mod kbs;

#[async_trait]
pub trait GetToken {
    async fn get_token(service_url: String) -> Result<Vec<u8>>;
}
