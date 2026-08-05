// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

/// WASM layer media type. WASM layers are stored uncompressed as a single
/// `module.wasm` binary, not as a tar archive.
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";

/// Encrypted WASM layer media type.
pub const WASM_LAYER_ENC_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm+encrypted";

/// Whether the given media type is a WASM layer (plain or encrypted).
pub fn is_wasm_media_type(media_type: &str) -> bool {
    media_type == WASM_LAYER_MEDIA_TYPE || media_type == WASM_LAYER_ENC_MEDIA_TYPE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wasm_media_type() {
        assert!(is_wasm_media_type(WASM_LAYER_MEDIA_TYPE));
        assert!(is_wasm_media_type(WASM_LAYER_ENC_MEDIA_TYPE));
        assert!(!is_wasm_media_type(
            "application/vnd.oci.image.layer.v1.tar+gzip"
        ));
        assert!(!is_wasm_media_type(""));
    }
}
