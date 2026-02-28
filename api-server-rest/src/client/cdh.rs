// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::TTRPC_TIMEOUT;
use anyhow::*;
use protos::ttrpc::cdh::api::GetResourceRequest;
use protos::ttrpc::cdh::api_ttrpc::GetResourceServiceClient;

/// ROOT path for Confidential Data Hub API
pub const CDH_ROOT: &str = "/cdh";

/// URL for querying CDH get resource API
pub const CDH_RESOURCE_URL: &str = "/resource";

const KBS_PREFIX: &str = "kbs://";

pub struct CDHClient {
    client: GetResourceServiceClient,
}

impl CDHClient {
    pub async fn new(cdh_addr: &str) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr)
            .await
            .context(format!("ttrpc connect to CDH addr: {cdh_addr} failed!"))?;
        let client = GetResourceServiceClient::new(inner);

        Ok(Self { client })
    }

    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: format!("{KBS_PREFIX}{resource_path}"),
            ..Default::default()
        };
        let res = self
            .client
            .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Resource)
    }
}
