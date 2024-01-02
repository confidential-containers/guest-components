// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;

pub(super) async fn get_public_key(keyid: &str) -> Result<Vec<u8>> {
    #[cfg(feature = "confidential-data-hub")]
    {
        use super::{api::GetPublicKeyRequest, api_ttrpc::GetPublicKeyServiceClient};
        const CONFIDENTIAL_DATA_HUB_SOCKET: &str = "unix:///run/confidential-containers/cdh.sock";
        const TTRPC_TIMEOUT: i64 = 50 * 1000 * 1000 * 1000;

        let inner = ttrpc::asynchronous::Client::connect(CONFIDENTIAL_DATA_HUB_SOCKET)?;
        let client = GetPublicKeyServiceClient::new(inner);

        let req = GetPublicKeyRequest {
            KeyId: keyid.to_string(),
            ..Default::default()
        };
        let res = client
            .get_public_key(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.PublicKeyPem)
    }

    #[cfg(not(feature = "confidential-data-hub"))]
    {
        crate::resource::get_resource(keyid).await
    }
}
