// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

// KBS specific packet
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    // This is an example annotation packet format.
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrap_type: String,
}
