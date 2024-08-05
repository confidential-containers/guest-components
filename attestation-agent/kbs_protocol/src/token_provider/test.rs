// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a mocked token provider which only for tests

use async_trait::async_trait;

use crate::{Error, Result, TeeKeyPair, Token};

use super::TokenProvider;

#[derive(Default)]
pub struct TestTokenProvider {}

/// A test Token expired in ~ 10years.
const HARDCODED: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6InNpbXBsZSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTA3ODk2MTgsImV4cCI6MjAwNjE0OTYxOCwibmJmIjoxNjkwNzg5NjE4fQ._rGIt6XRHXfMiypJ38G55Qit5XiGEEQz1vvGjPE3jUJheJAbAfU4qR3BnsTVbchSTagwMgz2U45iA5eGiMo3sQ";

#[async_trait]
impl TokenProvider for TestTokenProvider {
    async fn get_token(&self) -> Result<(Token, TeeKeyPair)> {
        let token =
            Token::new(HARDCODED.to_string()).map_err(|e| Error::GetTokenFailed(e.to_string()))?;
        let key = TeeKeyPair::new().map_err(|e| Error::GenerateKeyPairFailed(e.to_string()))?;
        Ok((token, key))
    }
}
