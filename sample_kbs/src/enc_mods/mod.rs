// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "sample_enc")]
pub mod sample_enc;
#[cfg(feature = "sample_enc")]
pub use sample_enc::enc_optsdata_gen_anno;
