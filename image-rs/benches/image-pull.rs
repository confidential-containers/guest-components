// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use image_rs::image::ImageClient;
use std::{fs, path::Path, time::Duration};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

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
        return entries.map(|entry| get_total_file_size(&entry.unwrap().path())).sum();
    }

    0
}

fn pull_image() -> u64 {
    let image_url = "ghcr.io/confidential-containers/test-container:unencrypted";
    let bundle_dir = tempfile::tempdir().unwrap();
    let bundle_dir_path = bundle_dir.path().to_path_buf();
    let mut image_client = ImageClient::new(bundle_dir.path().to_path_buf());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let bundle_dir_path_clone = bundle_dir_path.clone();
    runtime.block_on(async move { 
        image_client.pull_image(image_url, &bundle_dir_path_clone, &None, &None).await 
    }).unwrap();
    let data_dir = bundle_dir_path.join("layers");
    let total_size = get_total_file_size(&data_dir);

    drop(bundle_dir);
    total_size
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("image-pull");
    group.sample_size(10);
    
    // Run once to get the data size for throughput calculation
    let sample_size = pull_image();
    group.throughput(Throughput::Bytes(sample_size));
    
    group.bench_function("pull_image", |b| {
        b.iter_custom(|iters| {
            let mut total_duration = Duration::new(0, 0);
            
            for _ in 0..iters {
                let start = std::time::Instant::now();
                pull_image();
                let elapsed = start.elapsed();
                
                total_duration += elapsed;
            }
            
            total_duration
        });
    });
    
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);