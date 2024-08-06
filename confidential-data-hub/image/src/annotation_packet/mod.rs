// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod v1;
pub mod v2;

pub use v2::AnnotationPacketV2 as AnnotationPacket;

#[cfg(test)]
mod tests {
    use super::AnnotationPacket;

    #[test]
    fn compatiblity_with_old_packets() {
        let v1_raw = include_str!("../../test/v1.json");
        let _: AnnotationPacket = serde_json::from_str(v1_raw).expect("unable to parse V1 with V2");
    }
}
