// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait;

#[derive(Default)]
pub struct FakeSeAttest {}

#[async_trait::async_trait]
pub trait SeImplAttester {
    fn is_se_guest(&self) -> bool;
    async fn perform(&self, _request: Vec<u8>, _userdata: Vec<u8>) -> Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl SeImplAttester for FakeSeAttest {
    fn is_se_guest(&self) -> bool {
        false
    }

    async fn perform(&self, _request: Vec<u8>, _userdata: Vec<u8>) -> Result<Vec<u8>> {
        Result::Ok("test".as_bytes().to_vec())
    }
}
