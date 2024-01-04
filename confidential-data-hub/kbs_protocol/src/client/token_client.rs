// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use kbs_types::{ErrorInformation, Response};
use log::{debug, warn};
use resource_uri::ResourceUri;

use crate::{
    api::KbsClientCapabilities,
    client::{KbsClient, KBS_GET_RESOURCE_MAX_ATTEMPT, KBS_PREFIX},
    token_provider::TokenProvider,
    Error, Result,
};

impl KbsClient<Box<dyn TokenProvider>> {
    async fn update_token(&mut self) -> Result<()> {
        let (token, teekey) = self
            .provider
            .get_token()
            .await
            .map_err(|e| Error::GetTokenFailed(e.to_string()))?;
        self.token = Some(token);
        self.tee_key = teekey;
        Ok(())
    }
}

#[async_trait]
impl KbsClientCapabilities for KbsClient<Box<dyn TokenProvider>> {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let remote_url = format!(
            "{}/{KBS_PREFIX}/resource/{}/{}/{}",
            self.kbs_host_url, resource_uri.repository, resource_uri.r#type, resource_uri.tag
        );
        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            debug!("KBS client: trying to request KBS, attempt {attempt}");
            if self.token.is_none() {
                self.update_token().await?;
            }

            let token = self.token.as_ref().expect("token must have been got");

            let res = self
                .http_client
                .get(&remote_url)
                .bearer_auth(&token.content)
                .send()
                .await
                .map_err(|e| Error::HttpError(format!("get failed: {e}")))?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res
                        .json::<Response>()
                        .await
                        .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?;
                    let payload_data = self
                        .tee_key
                        .decrypt_response(response)
                        .map_err(|e| Error::DecryptResponseFailed(e.to_string()))?;
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    warn!(
                        "Authenticating with KBS failed. Get a new token from the token provider: {:#?}",
                        res.json::<ErrorInformation>().await.map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );
                    self.update_token().await?;

                    continue;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    let errorinfo = format!(
                        "KBS resource Not Found (Error 404): {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::ResourceNotFound(errorinfo));
                }
                _ => {
                    let errorinfo = format!(
                        "KBS Server Internal Failed, Response: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::KbsInternalError(errorinfo));
                }
            }
        }

        Err(Error::UnAuthorized)
    }
}
