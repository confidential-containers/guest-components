# image-rs

Container Images Rust Crate

## Documentation

[Design document](docs/design.md)

[CCv1 Image Security Design document](docs/ccv1_image_security_design.md)

## Performance Testing

This crate includes benchmark tests to measure image pull throughput and memory consumption.
We use [cargo bench](https://doc.rust-lang.org/cargo/commands/cargo-bench.html) to test image pull throughput and [heaptrack](https://github.com/KDE/heaptrack) for memory consumption.

### Running Benchmarks

#### Prerequisites

Install heaptrack for memory consumption analysis:

```bash
sudo apt install heaptrack -y
```

#### Running the Benchmark

To run the image pull benchmark:

```bash
heaptrack cargo bench -p image-rs --bench image-pull
```

The benchmark measures:
- Image pull time
- Throughput (MiB per second)

#### Understanding the Results

**Throughput Results**

Detailed performance metrics and visualizations are generated in the `target/criterion/` directory.
At the same time, a summary is displayed in the terminal:

```
image-pull/ghcr.io/confidential-containers/test-container:unencrypted
                        time:   [2.3829 s 2.4001 s 2.4197 s]
                        thrpt:  [3.5598 MiB/s 3.5889 MiB/s 3.6148 MiB/s]
                 change:
                        time:   [−3.7930% −0.9001% +1.3846%] (p = 0.61 > 0.05)
                        thrpt:  [−1.3657% +0.9083% +3.9425%]
                        No change in performance detected.
```

**Memory Consumption Report**

After the benchmark completes, heaptrack will display a command to analyze the memory data:

```
Heaptrack finished! Now run the following to investigate the data:

  heaptrack --analyze "xxxx/heaptrack.cargo.3133205.zst"
```

Run the provided command to generate the memory consumption report:

```bash
heaptrack --analyze "xxxx/heaptrack.cargo.3133205.zst"
```

The report includes metrics such as:

```
bytes allocated in total (ignoring deallocations): 51.85MB (328.14MB/s)
calls to allocation functions: 237333 (1502107/s)
temporary memory allocations: 89438 (566063/s)
peak heap memory consumption: 14.17MB
peak RSS (including heaptrack overhead): 126.19MB
total memory leaked: 1.14MB
```