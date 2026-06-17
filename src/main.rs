use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, TRANSFER_ENCODING};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::Method;
use tokio::net::{TcpListener, TcpStream};

/// Upstream npm registry that allowed requests are forwarded to.
const NPM_REGISTRY: &str = "https://registry.npmjs.org";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A gate that proxies npm package manager requests, screening packages for
/// supply-chain risks before forwarding them to the npm registry.
#[derive(Debug, Parser)]
#[command(name = "package-chain-gate", version, about)]
struct Cli {
    /// Port to listen on for npm proxy requests.
    #[arg(long, value_name = "PORT", default_value_t = 4873)]
    proxy_port: u16,
}

/// Builds the local address the proxy listens on for the given port.
fn listen_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    run(Cli::parse()).await
}

/// Binds the proxy listener and serves requests until the process is stopped.
async fn run(cli: Cli) -> Result<(), BoxError> {
    let listener = TcpListener::bind(listen_addr(cli.proxy_port)).await?;
    println!(
        "package-chain-gate listening for npm proxy requests on {} (upstream: {NPM_REGISTRY})",
        listener.local_addr()?
    );

    serve(listener, reqwest::Client::new(), Arc::from(NPM_REGISTRY)).await
}

/// Runs the accept loop, serving each accepted connection on its own task.
async fn serve(
    listener: TcpListener,
    client: reqwest::Client,
    upstream: Arc<str>,
) -> Result<(), BoxError> {
    loop {
        let (socket, peer) = listener.accept().await?;
        let client = client.clone();
        let upstream = Arc::clone(&upstream);

        // Each connection is handled independently so a slow client can't block
        // the accept loop.
        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, client, upstream).await {
                eprintln!("connection from {peer} failed: {err}");
            }
        });
    }
}

/// Serves HTTP/1 on a single client connection, proxying each request.
async fn handle_connection(
    socket: TcpStream,
    client: reqwest::Client,
    upstream: Arc<str>,
) -> Result<(), BoxError> {
    let io = TokioIo::new(socket);
    let service = service_fn(move |req| proxy(req, client.clone(), Arc::clone(&upstream)));

    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// Proxies a single npm request to the upstream registry and relays the response
/// back to the client.
///
/// TODO: before forwarding, screen the requested package for supply-chain risks
/// (malware, typosquatting, dependency confusion) and block disallowed requests.
async fn proxy(
    req: Request<Incoming>,
    client: reqwest::Client,
    upstream: Arc<str>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let (parts, body) = req.into_parts();

    // Preserve the original path and query (e.g. `/lodash` or
    // `/lodash/-/lodash-4.17.21.tgz`) when targeting the registry.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_owned();

    let body = body.collect().await?.to_bytes();

    forward(
        &client,
        &upstream,
        parts.method,
        parts.headers,
        &path_and_query,
        body,
    )
    .await
}

/// Forwards a request to the upstream registry and builds a relayed response.
///
/// Kept separate from [`proxy`] so the forwarding logic can be exercised without
/// constructing a live hyper request.
async fn forward(
    client: &reqwest::Client,
    upstream: &str,
    method: Method,
    mut headers: HeaderMap,
    path_and_query: &str,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let url = format!("{upstream}{path_and_query}");

    strip_hop_by_hop(&mut headers);
    // The host must match the upstream, so let the client set it.
    headers.remove(HOST);

    let upstream_response = client
        .request(method, &url)
        .headers(headers)
        .body(body)
        .send()
        .await?;

    let status = upstream_response.status();
    let mut response_headers = upstream_response.headers().clone();
    strip_hop_by_hop(&mut response_headers);
    let body = upstream_response.bytes().await?;

    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    Ok(response)
}

/// Removes hop-by-hop headers, which are connection-specific and must not be
/// forwarded by a proxy. `content-length` is dropped so it is recomputed for the
/// relayed body.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for header in [CONNECTION, TRANSFER_ENCODING, CONTENT_LENGTH] {
        headers.remove(header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spawns a stub upstream registry that echoes the requested path back in
    /// the response body, and returns its base URL.
    async fn spawn_stub_registry() -> Arc<str> {
        let listener = TcpListener::bind(listen_addr(0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(socket);
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let path = req.uri().path().to_owned();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            format!("upstream:{path}"),
                        ))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        Arc::from(format!("http://{addr}"))
    }

    /// Spawns the proxy in front of the given upstream and returns its socket
    /// address as `host:port`.
    async fn spawn_proxy(upstream: Arc<str>) -> String {
        let listener = TcpListener::bind(listen_addr(0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, reqwest::Client::new(), upstream));
        addr.to_string()
    }

    #[test]
    fn proxy_port_defaults_to_4873_when_omitted() {
        let cli = Cli::try_parse_from(["package-chain-gate"]).unwrap();
        assert_eq!(cli.proxy_port, 4873);
    }

    #[test]
    fn proxy_port_uses_specified_value() {
        let cli = Cli::try_parse_from(["package-chain-gate", "--proxy-port", "8080"]).unwrap();
        assert_eq!(cli.proxy_port, 8080);
    }

    #[test]
    fn proxy_port_rejects_out_of_range_value() {
        // 65536 is one past the maximum u16 port.
        let result = Cli::try_parse_from(["package-chain-gate", "--proxy-port", "65536"]);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_port_rejects_non_numeric_value() {
        let result = Cli::try_parse_from(["package-chain-gate", "--proxy-port", "abc"]);
        assert!(result.is_err());
    }

    #[test]
    fn listen_addr_binds_localhost_with_given_port() {
        let addr = listen_addr(4873);
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(addr.port(), 4873);
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_specific_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive".parse().unwrap());
        headers.insert(CONTENT_LENGTH, "2".parse().unwrap());
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(HOST, "example.com".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key(CONTENT_LENGTH));
        assert!(!headers.contains_key(TRANSFER_ENCODING));
        // `host` is not hop-by-hop; it is removed separately during forwarding.
        assert!(headers.contains_key(HOST));
    }

    #[tokio::test]
    async fn run_binds_and_serves_until_cancelled() {
        // Port 0 lets the OS assign a free port. `run` serves forever, so it is
        // cancelled by the timeout once it is up and accepting.
        let outcome =
            tokio::time::timeout(Duration::from_millis(100), run(Cli { proxy_port: 0 })).await;
        assert!(
            outcome.is_err(),
            "run() should still be serving when cancelled"
        );
    }

    #[tokio::test]
    async fn forwards_package_fetch_to_registry() {
        let upstream = spawn_stub_registry().await;
        let proxy = spawn_proxy(upstream).await;

        // Simulate npm fetching package metadata.
        let response = reqwest::get(format!("http://{proxy}/lodash"))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "upstream:/lodash");
    }

    #[tokio::test]
    async fn forwards_tarball_path_and_query_to_registry() {
        let upstream = spawn_stub_registry().await;
        let proxy = spawn_proxy(upstream).await;

        // Simulate npm fetching a package tarball.
        let response = reqwest::get(format!("http://{proxy}/lodash/-/lodash-4.17.21.tgz"))
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.unwrap(),
            "upstream:/lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[tokio::test]
    async fn forward_relays_upstream_status_and_body() {
        let upstream = spawn_stub_registry().await;
        let client = reqwest::Client::new();

        let mut headers = HeaderMap::new();
        headers.insert(HOST, "should-be-replaced".parse().unwrap());

        let response = forward(
            &client,
            &upstream,
            Method::GET,
            headers,
            "/lodash",
            Bytes::new(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"upstream:/lodash");
    }

    #[tokio::test]
    async fn forward_errors_when_upstream_is_unreachable() {
        let client = reqwest::Client::new();
        // Port 1 is privileged and refuses connections, forcing a request error.
        let result = forward(
            &client,
            "http://127.0.0.1:1",
            Method::GET,
            HeaderMap::new(),
            "/lodash",
            Bytes::new(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_connection_completes_on_connection_close() {
        let upstream = spawn_stub_registry().await;
        let proxy = spawn_proxy(upstream).await;

        let mut stream = TcpStream::connect(&proxy).await.unwrap();
        stream
            .write_all(b"GET /lodash HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn serve_logs_error_on_malformed_request() {
        let upstream = spawn_stub_registry().await;
        let proxy = spawn_proxy(upstream).await;

        let mut stream = TcpStream::connect(&proxy).await.unwrap();
        stream.write_all(b"NOT-HTTP GARBAGE\r\n\r\n").await.unwrap();

        // The connection-handling task should fail and close the socket.
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        // Let the spawned task run its error branch before the test ends.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
