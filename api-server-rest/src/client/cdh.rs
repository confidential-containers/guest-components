// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::client::ttrpc_client::CachedTtrpcClient;
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
    client: CachedTtrpcClient<GetResourceServiceClient>,
}

impl CDHClient {
    pub async fn new(cdh_addr: &str) -> Result<Self> {
        let client = CachedTtrpcClient::new(cdh_addr, "CDH", GetResourceServiceClient::new).await?;

        Ok(Self { client })
    }

    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let resource_path = format!("{KBS_PREFIX}{resource_path}");

        let res = self
            .client
            .call_with_retry(|client| {
                let resource_path = resource_path.clone();

                async move {
                    let req = GetResourceRequest {
                        ResourcePath: resource_path,
                        ..Default::default()
                    };

                    client
                        .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                        .await
                }
            })
            .await?;

        Ok(res.Resource)
    }
}
