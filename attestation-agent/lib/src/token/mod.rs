// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[cfg(feature = "kbs")]
pub mod kbs;

#[cfg(feature = "coco_as")]
pub mod coco_as;

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum TokenType {
    #[cfg(feature = "kbs")]
    #[serde(rename = "kbs")]
    Kbs,

    #[cfg(feature = "coco_as")]
    #[serde(rename = "coco_as")]
    CoCoAS,
}

#[async_trait]
pub trait GetToken {
    async fn get_token(&self, service_url: String) -> Result<Vec<u8>>;
}
