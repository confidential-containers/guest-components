// Copyright (c) 2023. Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_api::BuildTimeInfo;
use oci_distribution::manifest;

pub fn is_nydus_data_layer(desc: &manifest::OciDescriptor) -> bool {
    desc.annotations
        .as_ref()
        .map(|v| v.contains_key(super::NYDUS_DATA_LAYER))
        .unwrap_or_default()
}

pub fn is_nydus_meta_layer(desc: &manifest::OciDescriptor) -> bool {
    desc.annotations
        .as_ref()
        .map(|v| v.contains_key(super::NYDUS_META_LAYER))
        .unwrap_or_default()
}

pub fn is_nydus_image(image_manifest: &manifest::OciImageManifest) -> bool {
    get_nydus_bootstrap_desc(image_manifest).is_some()
}

pub fn get_nydus_bootstrap_desc(
    image_manifest: &manifest::OciImageManifest,
) -> Option<manifest::OciDescriptor> {
    let layers = &image_manifest.layers;
    if !layers.is_empty() {
        let desc = &layers[layers.len() - 1];
        if is_nydus_meta_layer(desc) {
            Some(desc.clone())
        } else {
            None
        }
    } else {
        None
    }
}

/// TODO replace these hardcoded build info
pub fn get_build_time_info() -> BuildTimeInfo {
    BuildTimeInfo {
        package_ver: "".to_string(),
        git_commit: "".to_string(),
        build_time: "".to_string(),
        profile: "".to_string(),
        rustc: "".to_string(),
    }
}
