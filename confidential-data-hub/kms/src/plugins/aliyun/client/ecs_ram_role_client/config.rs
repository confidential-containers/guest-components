// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Configs to access aliyun KMS

#[derive(Clone, Debug)]
pub(crate) struct ConfigEcsRamRole {
    pub region_id: String,
    pub endpoint: String,
    pub _vpc: String,
}

// implement ConfigEcsRamRole related function
impl ConfigEcsRamRole {
    pub(crate) fn new(region_id: &str, endpoint: &str, vpc: &str) -> Self {
        Self {
            region_id: region_id.to_string(),
            endpoint: endpoint.to_string(),
            _vpc: vpc.to_string(),
        }
    }
}
