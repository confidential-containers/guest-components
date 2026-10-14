// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use reqwest::Url;
use tracing::debug;

const KBS_URL_PATH_PREFIX: &str = "kbs/v0/resource";

/// Register the given key with kid into the kbs. This request will be authorized with a
/// JWT token, which will be signed by the private_key.
pub(crate) async fn register_kek(
    private_key: &Ed25519KeyPair,
    kbs_addr: &Url,
    key: Vec<u8>,
    kid: &str,
) -> Result<()> {
    let kid = kid.strip_prefix('/').unwrap_or(kid);
    let claims = Claims::create(Duration::from_hours(2));
    let token = private_key.sign(claims)?;
    debug!("sign claims.");

    let client = reqwest::Client::new();
    let mut resource_url = kbs_addr.clone();

    let path = format!("{KBS_URL_PATH_PREFIX}/{kid}");

    resource_url.set_path(&path);

    debug!("register KEK into {resource_url}");
    let response = client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(token)
        .body(key)
        .send()
        .await?;

    // `?` above only covers transport errors, so the status has to be checked here:
    // otherwise a KBS that rejects the registration is reported as a success.
    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|e| format!("<unreadable body: {e}>"));
        bail!("KBS rejected the KEK registration for {kid}: HTTP {status}: {body}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Answer exactly one request with `status_line`, then return.
    async fn serve_once(listener: TcpListener, status_line: &'static str, body: &'static str) {
        // `.ok()` rather than an `Ok(..)` pattern: this module does `use anyhow::*`, which
        // brings `anyhow::Ok` (a function) into scope and shadows the variant in patterns.
        let Some((mut socket, _)) = listener.accept().await.ok() else {
            return;
        };
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let response = format!(
            "HTTP/1.1 {status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.flush().await;
    }

    async fn register_against(status_line: &'static str, body: &'static str) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(serve_once(listener, status_line, body));

        let url = Url::parse(&format!("http://{addr}")).expect("url");
        let key_pair = Ed25519KeyPair::generate();
        let result = register_kek(
            &key_pair,
            &url,
            b"0123456789abcdef".to_vec(),
            "repo/type/tag",
        )
        .await;

        let _ = server.await;
        result
    }

    #[tokio::test]
    async fn rejects_unauthorized_registration() {
        let err = register_against("401 Unauthorized", "invalid signature")
            .await
            .expect_err("a 401 must not be reported as a successful registration");
        let msg = err.to_string();
        assert!(msg.contains("401"), "status belongs in the error: {msg}");
        assert!(
            msg.contains("repo/type/tag"),
            "kid belongs in the error: {msg}"
        );
        assert!(
            msg.contains("invalid signature"),
            "body belongs in the error: {msg}"
        );
    }

    #[tokio::test]
    async fn rejects_server_error() {
        let err = register_against("500 Internal Server Error", "boom")
            .await
            .expect_err("a 5xx must not be reported as a successful registration");
        assert!(err.to_string().contains("500"));
    }

    #[tokio::test]
    async fn accepts_success() {
        register_against("200 OK", "")
            .await
            .expect("a 2xx registration must succeed");
    }
}
