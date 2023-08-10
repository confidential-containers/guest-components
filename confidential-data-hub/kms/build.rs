#![allow(missing_docs)]

// extern crate tonic_build;

use anyhow::*;

fn main() -> Result<()> {
    #[cfg(feature = "aliyun")]
    tonic_build::compile_protos("./src/plugins/aliyun/protobuf/dkms_api.proto")?;

    #[cfg(feature = "sev")]
    tonic_build::configure()
        .build_server(true)
        .out_dir("./src/plugins/sev")
        .compile(&["./src/plugins/sev/protos/getsecret.proto"], &[""])?;

    Ok(())
}
