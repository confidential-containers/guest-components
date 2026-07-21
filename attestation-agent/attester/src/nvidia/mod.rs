// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(target_arch = "x86_64")]
mod nvat;
#[cfg(target_arch = "x86_64")]
pub use nvat::{detect_platform, NvAttester};

#[cfg(not(target_arch = "x86_64"))]
mod unsupported;
#[cfg(not(target_arch = "x86_64"))]
pub use unsupported::{detect_platform, NvAttester};
