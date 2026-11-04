// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::StreamProcessor;

#[derive(Debug)]
pub struct NullProcessor;

impl StreamProcessor for NullProcessor {
    fn process_input(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        eprintln!("stream_processor: null process_input len: {} ", data.len());
        // eprintln!("stream_processor: null process_input data: {:?} ", data);
        Ok(data.to_vec())
    }

    fn process_output(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        eprintln!("stream_processor: null process_output len: {} ", data.len());
        // eprintln!("stream_processor: null process_output data: {:?} ", data);
        Ok(data.to_vec())
    }
}
