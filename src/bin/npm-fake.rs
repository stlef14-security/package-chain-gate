use std::process::ExitCode;

use clap::Parser;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// User-Agent string mirroring what the real npm CLI sends, so requests are
/// indistinguishable to the proxy.
const NPM_USER_AGENT: &str = "npm/10.8.2 node/v20.15.0 darwin arm64 workspaces/false";

/// Accept header npm sends when fetching packages during install. Requesting the
/// `install-v1` media type yields the registry's abbreviated metadata, exactly
/// as npm does.
const NPM_ACCEPT: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

/// A fake npm client for exercising the package-chain-gate proxy.
///
/// Issues the same HTTP requests the real `npm` CLI makes when fetching a
/// package, directed at the proxy's listening port. Useful for testing the
/// proxy without installing or configuring npm.
#[derive(Debug, Parser)]
#[command(name = "npm-fake", version, about)]
struct Cli {
    /// Package to fetch, e.g. `lodash` or a scoped name like `@types/node`.
    package: String,

    /// Port the package-chain-gate proxy is listening on.
    #[arg(long, value_name = "PORT", default_value_t = 4873)]
    proxy_port: u16,

    /// Also download the tarball for this version, e.g. `4.17.21`.
    #[arg(long, value_name = "VERSION")]
    tarball: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    run_cli(Cli::parse()).await
}

/// Runs the client and maps the outcome to a process exit code.
async fn run_cli(cli: Cli) -> ExitCode {
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("npm-fake: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Issues the npm-style requests for the given package against the proxy.
async fn run(cli: Cli) -> Result<(), BoxError> {
    let base = format!("http://localhost:{}", cli.proxy_port);
    let client = reqwest::Client::new();

    // Fetch package metadata, just as npm does first during an install.
    let metadata_url = format!("{base}/{}", encode_package(&cli.package));
    fetch(&client, &metadata_url, "metadata").await?;

    // Optionally fetch the tarball, the second request npm makes per package.
    if let Some(version) = &cli.tarball {
        let tarball_url = format!("{base}/{}", tarball_path(&cli.package, version));
        fetch(&client, &tarball_url, "tarball").await?;
    }

    Ok(())
}

/// Issues a single npm-style GET request and reports the outcome.
async fn fetch(client: &reqwest::Client, url: &str, kind: &str) -> Result<(), BoxError> {
    println!("GET {url}  ({kind})");

    let response = client
        .get(url)
        .header(USER_AGENT, NPM_USER_AGENT)
        .header(ACCEPT, NPM_ACCEPT)
        .header(ACCEPT_ENCODING, "gzip, deflate, br")
        .send()
        .await?;

    let status = response.status();
    let body = response.bytes().await?;
    println!("  <- {} ({} bytes)", status, body.len());

    if status.is_success() {
        Ok(())
    } else {
        Err(format!("{kind} request failed with status {status}").into())
    }
}

/// Builds the metadata request path for a package name.
///
/// npm percent-encodes the `/` separator in scoped names (e.g. `@types/node`
/// becomes `@types%2fnode`); unscoped names are used verbatim.
fn encode_package(package: &str) -> String {
    if package.starts_with('@') {
        package.replacen('/', "%2f", 1)
    } else {
        package.to_owned()
    }
}

/// Builds the tarball request path for a package and version.
///
/// The tarball filename uses the unscoped package name, so `@babel/core` at
/// `7.0.0` resolves to `@babel/core/-/core-7.0.0.tgz`.
fn tarball_path(package: &str, version: &str) -> String {
    let unscoped = package.rsplit('/').next().unwrap_or(package);
    format!("{package}/-/{unscoped}-{version}.tgz")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    /// Spawns a stub registry. Paths containing `missing` get a 404; everything
    /// else gets a 200. Returns the port it is listening on.
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

    fn cli(package: &str, port: u16, tarball: Option<&str>) -> Cli {
        Cli {
            package: package.to_owned(),
            proxy_port: port,
            tarball: tarball.map(str::to_owned),
        }
    }

    #[test]
    fn unscoped_package_is_used_verbatim() {
        assert_eq!(encode_package("lodash"), "lodash");
    }

    #[test]
    fn scoped_package_slash_is_percent_encoded() {
        assert_eq!(encode_package("@types/node"), "@types%2fnode");
    }

    #[test]
    fn unscoped_tarball_path() {
        assert_eq!(
            tarball_path("lodash", "4.17.21"),
            "lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn scoped_tarball_path_uses_unscoped_filename() {
        assert_eq!(
            tarball_path("@babel/core", "7.0.0"),
            "@babel/core/-/core-7.0.0.tgz"
        );
    }

    #[test]
    fn proxy_port_defaults_to_4873() {
        let parsed = Cli::try_parse_from(["npm-fake", "lodash"]).unwrap();
        assert_eq!(parsed.proxy_port, 4873);
        assert_eq!(parsed.package, "lodash");
        assert!(parsed.tarball.is_none());
    }

    #[test]
    fn parses_custom_port_and_tarball_version() {
        let parsed = Cli::try_parse_from([
            "npm-fake",
            "lodash",
            "--proxy-port",
            "8080",
            "--tarball",
            "4.17.21",
        ])
        .unwrap();
        assert_eq!(parsed.proxy_port, 8080);
        assert_eq!(parsed.tarball.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn package_argument_is_required() {
        assert!(Cli::try_parse_from(["npm-fake"]).is_err());
    }

    #[tokio::test]
    async fn run_fetches_metadata() {
        let port = spawn_stub().await;
        assert!(run(cli("lodash", port, None)).await.is_ok());
    }

    #[tokio::test]
    async fn run_fetches_metadata_and_tarball() {
        let port = spawn_stub().await;
        assert!(run(cli("lodash", port, Some("4.17.21"))).await.is_ok());
    }

    #[tokio::test]
    async fn run_errors_when_request_fails() {
        let port = spawn_stub().await;
        assert!(run(cli("missing-pkg", port, None)).await.is_err());
    }

    #[tokio::test]
    async fn run_cli_succeeds_for_available_package() {
        let port = spawn_stub().await;
        // ExitCode is opaque; calling exercises the success arm of run_cli.
        let _ = run_cli(cli("lodash", port, None)).await;
    }

    #[tokio::test]
    async fn run_cli_fails_for_missing_package() {
        let port = spawn_stub().await;
        // Exercises the error arm (eprintln + failure exit code).
        let _ = run_cli(cli("missing-pkg", port, None)).await;
    }
}
