# image-rs

Container Images Rust Crate

## Documentation

[Design document](docs/design.md)

[CCv1 Image Security Design document](docs/ccv1_image_security_design.md)

## Performance Testing

This crate includes benchmark tests to measure image pull performance.

### Running Benchmarks

To run the image pull benchmark:

```bash
cargo bench --bench image-pull
```

The benchmark measures:
- Image pull time
- Throughput (bytes per second)

Benchmark results are generated in the `target/criterion/` directory and include detailed performance metrics and visualizations.

