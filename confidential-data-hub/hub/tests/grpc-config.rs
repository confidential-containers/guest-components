// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#![cfg(all(feature = "bin", feature = "grpc"))]

// Run with --no-default-features --features bin,grpc for root-free startup.
// The kbs feature initializes resources under /run and requires root/fixtures.
use std::{io::Write, net::TcpListener, path::Path, process::Stdio, time::Duration};

use hyper_util::rt::TokioIo;
use protos::grpc::cdh::api::{UnsealSecretInput, UnsealSecretOutput};
use rstest::rstest;
use tokio::{net::UnixStream, process::Command, time::timeout};
use tonic::{client::Grpc, codegen::http::uri::PathAndQuery, transport::Channel, Code, Request};
use tower::service_fn;

const SERVICES: [(&str, &str); 4] = [
    ("imagepull", "/api.ImagePullService/PullImage"),
    ("sealedsecrets", "/api.SealedSecretService/UnsealSecret"),
    ("securemount", "/api.SecureMountService/SecureMount"),
    ("getresource", "/api.GetResourceService/GetResource"),
];

async fn unix_channel(path: &Path) -> Channel {
    let path = path.to_owned();
    Channel::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .unwrap()
}

async fn call_route(channel: Channel, route: &'static str) -> tonic::Status {
    let mut client = Grpc::new(channel);
    client.ready().await.unwrap();
    // Invalid UTF-8 fails protobuf string decoding for image/mount/resource,
    // and sealed-secret parsing for unseal. No operation reaches external services.
    let request = Request::new(UnsealSecretInput { secret: vec![0xff] });
    timeout(
        Duration::from_secs(5),
        client.unary(
            request,
            PathAndQuery::from_static(route),
            tonic_prost::ProstCodec::<UnsealSecretInput, UnsealSecretOutput>::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap_err()
}

fn write_config(file: &mut impl Write, socket: &str, services_dir: Option<&Path>) {
    let mut config = serde_json::json!({
        "socket": socket,
        "kbc": {"name": "offline_fs_kbc"},
    });
    if let Some(dir) = services_dir {
        config["services_dir"] = serde_json::json!(dir);
    }
    write!(file, "{config}").unwrap();
}

#[rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn grpc_service_sockets(#[case] per_service: bool) {
    let temp = tempfile::tempdir().unwrap();
    let services_dir = temp.path().join("services");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config_file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    write_config(
        &mut config_file,
        &addr.to_string(),
        per_service.then_some(&services_dir),
    );
    let log_path = temp.path().join("server.log");
    let log = std::fs::File::create(&log_path).unwrap();
    drop(listener);
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("grpc-cdh"))
        .arg("-c")
        .arg(config_file.path())
        .env(
            "OCICRYPT_KEYPROVIDER_CONFIG",
            temp.path().join("ocicrypt.json"),
        )
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let combined = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = std::fs::read_to_string(&log_path).unwrap();
                panic!("CDH exited with {status}: {output}");
            }
            if let Ok(channel) = Channel::from_shared(format!("http://{addr}"))
                .unwrap()
                .connect()
                .await
            {
                break channel;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    for (name, route) in SERVICES {
        assert_eq!(
            call_route(combined.clone(), route).await.code(),
            Code::Internal
        );
        let path = services_dir.join(format!("{name}.sock"));
        if per_service {
            let channel = unix_channel(&path).await;
            for (_, candidate) in SERVICES {
                let expected = if candidate == route {
                    Code::Internal
                } else {
                    Code::Unimplemented
                };
                assert_eq!(
                    call_route(channel.clone(), candidate).await.code(),
                    expected,
                    "{name}: {candidate}"
                );
            }
            let status = call_route(channel, "/keyprovider.KeyProviderService/WrapKey").await;
            assert_eq!(status.code(), Code::Unimplemented);
            assert_ne!(status.message(), "WrapKey not implemented.");
        } else {
            assert!(!path.exists());
        }
    }
    // The combined endpoint retains the key-provider service.
    let status = call_route(combined, "/keyprovider.KeyProviderService/WrapKey").await;
    assert_eq!(status.message(), "WrapKey not implemented.");

    let pid = nix::unistd::Pid::from_raw(child.id().unwrap() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).unwrap();
    assert!(timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    if per_service {
        for (name, _) in SERVICES {
            assert!(
                UnixStream::connect(services_dir.join(format!("{name}.sock")))
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn grpc_service_socket_bind_failure_is_fatal() {
    let temp = tempfile::tempdir().unwrap();
    let services_dir = temp.path().join("services");
    std::fs::create_dir_all(services_dir.join("imagepull.sock")).unwrap();
    let mut config_file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    write_config(&mut config_file, "127.0.0.1:0", Some(&services_dir));
    let output = timeout(
        Duration::from_secs(10),
        Command::new(assert_cmd::cargo::cargo_bin!("grpc-cdh"))
            .arg("-c")
            .arg(config_file.path())
            .env(
                "OCICRYPT_KEYPROVIDER_CONFIG",
                temp.path().join("ocicrypt.json"),
            )
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(!services_dir.join("sealedsecrets.sock").exists());
}
