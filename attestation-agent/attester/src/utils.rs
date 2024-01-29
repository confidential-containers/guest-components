// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub fn pad<const T: usize>(input: &[u8]) -> [u8; T] {
    let mut output = [0; T];
    let len = input.len();
    if len > T {
        output.copy_from_slice(&input[..T]);
    } else {
        output[..len].copy_from_slice(input);
    }
    output
}
