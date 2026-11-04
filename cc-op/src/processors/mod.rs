// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub trait StreamProcessor: Send + Sync + std::fmt::Debug {
    fn process_input(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn process_output(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub mod aesgcm;
pub mod aesgcmtty;
pub mod null;
