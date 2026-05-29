// Copyright (c) 2026 Arqit / guest-components contributors.
// SPDX-License-Identifier: Apache-2.0

// Small test client for POC experimental feature "pqc-experimental"

// Usage: akp_get_resource <kbs_url> <kbs-resource-uri>
// e.g.   akp_get_resource http://127.0.0.1:8080 kbs:///default/test/dummy
// RUST_LOG=kbs_protocol=debug cargo run --no-default-features --features 'background_check,rust-crypto,pqc-experimental,bin' --example akp_get_resource -- http://127.0.0.1:8080 'kbs:///default/test/dummy'

use anyhow::anyhow;
use kbs_protocol::{
    evidence_provider::NativeEvidenceProvider, KbsClientBuilder, KbsClientCapabilities,
    TeeKeyAlgorithm,
};
use resource_uri::ResourceUri;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let mut args = std::env::args().skip(1);
    let url = args.next().expect("usage: akp_get_resource <url> <kbs-resource-uri>");
    let resource = args.next().expect("usage: akp_get_resource <url> <kbs-resource-uri>");

    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let mut client = KbsClientBuilder::with_evidence_provider(evidence_provider, &url)
        .set_tee_key_algorithm(TeeKeyAlgorithm::MlKem768A192Kw)
        .build()?;

    let uri: ResourceUri = resource
        .as_str()
        .try_into()
        .map_err(|e| anyhow!("invalid kbs resource URI: {e}"))?;
    let bytes = client.get_resource(uri).await?;
    println!("Got {} bytes:\n{}", bytes.len(), String::from_utf8_lossy(&bytes));
    Ok(())
}