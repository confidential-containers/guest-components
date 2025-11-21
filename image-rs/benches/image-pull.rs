// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use image_rs::image::ImageClient;
use nix::mount::umount;
use std::{fs, path::Path, time::Duration};

/// The image URLs to be pulled.
/// TODO: add more image URLs to be pulled.
const IMAGE_URLS: [&str; 1] = ["ghcr.io/confidential-containers/test-container:unencrypted"];

fn get_total_file_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }

    let metadata = fs::symlink_metadata(path).unwrap();

    if metadata.is_file() {
        return metadata.len();
    }

    if metadata.is_dir() {
        let entries = fs::read_dir(path).unwrap();
        return entries
            .map(|entry| get_total_file_size(&entry.unwrap().path()))
            .sum();
    }

    0
}

fn pull_image(image_url: &str) -> u64 {
    let bundle_dir = tempfile::tempdir().unwrap();
    let bundle_dir_path = bundle_dir.path().to_path_buf();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let bundle_dir_path_clone = bundle_dir_path.clone();
    let mut image_client = ImageClient::new(bundle_dir.path().to_path_buf());
    runtime
        .block_on(async move {
            image_client
                .pull_image(image_url, &bundle_dir_path_clone, &None, &None)
                .await
        })
        .unwrap();
    let data_dir = bundle_dir_path.join("rootfs");
    let total_size = get_total_file_size(&data_dir);

    umount(&data_dir).unwrap();
    drop(bundle_dir);
    total_size
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("image-pull");
    group.sample_size(10);

    for image_url in IMAGE_URLS {
        // Run once to get the data size for throughput calculation
        let sample_size = pull_image(image_url);
        group.throughput(Throughput::Bytes(sample_size));

        group.bench_function(image_url, |b| {
            b.iter_custom(|iters| {
                let mut total_duration = Duration::new(0, 0);

                for _ in 0..iters {
                    let start = std::time::Instant::now();
                    // let resident_before = resident.read().unwrap();
                    pull_image(image_url);
                    let elapsed = start.elapsed();

                    total_duration += elapsed;
                }

                total_duration
            });
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
