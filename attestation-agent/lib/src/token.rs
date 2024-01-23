// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::aa_kbc_params;
use anyhow::Result;
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

pub(crate) async fn get_kbs_token() -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

    let params = aa_kbc_params::get_params().await?;
    let kbs_host_url = params.uri();

    let mut client =
        KbsClientBuilder::with_evidence_provider(evidence_provider, kbs_host_url).build()?;

    let (token, tee_keypair) = client.get_token().await?;
    let message = Message {
        token: token.content,
        tee_keypair: tee_keypair.to_pkcs1_pem()?.to_string(),
    };

    let res = serde_json::to_vec(&message)?;
    Ok(res)
}
