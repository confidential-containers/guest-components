// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Configs to access aliyun KMS

#[derive(Clone, Debug)]
pub(crate) struct ConfigClientKey {
    pub kms_instance_id: String,
    pub endpoint: String,
}

// implement ConfigClientKey related function
impl ConfigClientKey {
    pub(crate) fn new(kms_instance_id: &str, endpoint: &str) -> Self {
        ConfigClientKey {
            kms_instance_id: kms_instance_id.to_string(),
            endpoint: endpoint.to_string(),
        }
    }
}
