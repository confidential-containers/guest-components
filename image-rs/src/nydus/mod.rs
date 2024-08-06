// Copyright (c) 2023. Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// A bool flag to mark the blob as a Nydus data blob, set by image builders.
pub const NYDUS_DATA_LAYER: &str = "containerd.io/snapshot/nydus-blob";
// A bool flag to mark the blob as a nydus bootstrap, set by image builders.
pub const NYDUS_META_LAYER: &str = "containerd.io/snapshot/nydus-bootstrap";
// A bool flag to mark the blob as a nydus ref metadata, set by image builders.
pub const NYDUS_REF_LAYER: &str = "containerd.io/snapshot/nydus-ref";
// Annotation containing secret to pull images from registry, set by the snapshotter.
pub const NYDUS_IMAGE_PULL_SECRET: &str = "containerd.io/snapshot/pullsecret";
// Annotation containing username to pull images from registry, set by the snapshotter.
pub const NYDUS_IMAGE_PULL_USERNAME: &str = "containerd.io/snapshot/pullusername";
// A bool flag to enable integrity verification of meta data blob
pub const NYDUS_SIGNATURE: &str = "containerd.io/snapshot/nydus-signature";

pub mod service;
pub mod utils;
