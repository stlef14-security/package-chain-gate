//! End-to-end test that runs the compiled `npm-fake` binary against a stub
//! registry. This exercises the binary's `main` entry point, which unit tests
//! cannot call directly.

use std::net::Ipv4Addr;
use std::process::Command;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

/// Spawns a stub registry on the given runtime and returns the port it listens
/// on. Paths containing `missing` get a 404; everything else gets a 200.
async fn spawn_stub() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = TokioIo::new(socket);
                let service = service_fn(|req: Request<Incoming>| async move {
                    let status = if req.uri().path().contains("missing") {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::OK
                    };
                    let mut response = Response::new(Full::new(Bytes::from_static(b"body")));
                    *response.status_mut() = status;
                    Ok::<_, std::convert::Infallible>(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    port
}

#[test]
fn npm_fake_binary_succeeds_for_available_package() {
    // The runtime is kept alive for the duration of the test so the stub task
    // keeps serving while the binary runs.
    let runtime = Runtime::new().unwrap();
    let port = runtime.block_on(spawn_stub());

    let output = Command::new(env!("CARGO_BIN_EXE_npm-fake"))
        .arg("lodash")
        .arg("--proxy-port")
        .arg(port.to_string())
        .arg("--tarball")
        .arg("4.17.21")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("/lodash"));
    assert!(stdout.contains("lodash-4.17.21.tgz"));
}

#[test]
fn npm_fake_binary_fails_for_missing_package() {
    let runtime = Runtime::new().unwrap();
    let port = runtime.block_on(spawn_stub());

    let output = Command::new(env!("CARGO_BIN_EXE_npm-fake"))
        .arg("missing-pkg")
        .arg("--proxy-port")
        .arg(port.to_string())
        .output()
        .unwrap();

    assert!(!output.status.success());
}
