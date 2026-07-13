use shadow_rs::{BuildPattern, ShadowBuilder};

fn main() -> std::io::Result<()> {
    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .unwrap();
    Ok(())
}
