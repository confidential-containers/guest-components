use shadow_rs::{BuildPattern, ShadowBuilder};

fn main() -> shadow_rs::SdResult<()> {
    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()?;
    Ok(())
}
