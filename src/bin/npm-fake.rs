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
    #[arg(required_unless_present = "purl", conflicts_with = "purl")]
    package: Option<String>,

    /// Port the package-chain-gate proxy is listening on.
    #[arg(long, value_name = "PORT", default_value_t = 4873)]
    proxy_port: u16,

    /// Also download the tarball for this version, e.g. `4.17.21`.
    #[arg(long, value_name = "VERSION", conflicts_with = "purl")]
    tarball: Option<String>,

    /// Full npm purl to fetch, e.g. `pkg:npm/lodash@4.17.21`. The version, when
    /// present, is fetched as a tarball. Mutually exclusive with the package
    /// argument and `--tarball`.
    #[arg(long, value_name = "PURL")]
    purl: Option<String>,
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

/// Issues the npm-style requests for the requested package against the proxy.
async fn run(cli: Cli) -> Result<(), BoxError> {
    let (package, version) = resolve_target(&cli)?;

    let base = format!("http://localhost:{}", cli.proxy_port);
    let client = reqwest::Client::new();

    // Fetch package metadata, just as npm does first during an install.
    let metadata_url = format!("{base}/{}", encode_package(&package));
    fetch(&client, &metadata_url, "metadata").await?;

    // Optionally fetch the tarball, the second request npm makes per package.
    if let Some(version) = &version {
        let tarball_url = format!("{base}/{}", tarball_path(&package, version));
        fetch(&client, &tarball_url, "tarball").await?;
    }

    Ok(())
}

/// Resolves the package name and optional version to fetch, from either a
/// `--purl` or the package argument plus `--tarball`.
fn resolve_target(cli: &Cli) -> Result<(String, Option<String>), BoxError> {
    match (&cli.purl, &cli.package) {
        (Some(purl), _) => {
            parse_npm_purl(purl).ok_or_else(|| format!("invalid npm purl: {purl}").into())
        }
        (None, Some(package)) => Ok((package.clone(), cli.tarball.clone())),
        (None, None) => Err("a package name or --purl is required".into()),
    }
}

/// Parses an npm purl (`pkg:npm/<name>[@<version>]`) into its package name and
/// optional version. Returns `None` for non-npm purls or an empty name/version.
fn parse_npm_purl(purl: &str) -> Option<(String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:npm/")?;
    // Drop any purl qualifiers (`?...`) or subpath (`#...`).
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }

    // The version follows the last `@`; a leading `@` (index 0) is the scope
    // marker of a scoped name, not a version separator.
    match rest.rfind('@') {
        Some(idx) if idx > 0 => {
            let version = &rest[idx + 1..];
            if version.is_empty() {
                None
            } else {
                Some((rest[..idx].to_owned(), Some(version.to_owned())))
            }
        }
        _ => Some((rest.to_owned(), None)),
    }
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
        return Ok(());
    }

    // Surface the response body as the failure reason; for blocked packages the
    // proxy returns a body naming the package and its vulnerabilities.
    let reason = String::from_utf8_lossy(&body);
    let reason = reason.trim();
    let message = if reason.is_empty() {
        format!("{kind} request failed with status {status}")
    } else {
        format!("{kind} request failed with status {status}: {reason}")
    };
    Err(message.into())
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
                        let path = req.uri().path();
                        let (status, body): (StatusCode, &'static [u8]) =
                            if path.contains("blocked") {
                                (StatusCode::FORBIDDEN, b"package is blocked (malware)")
                            } else if path.contains("noreason") {
                                (StatusCode::INTERNAL_SERVER_ERROR, b"")
                            } else if path.contains("missing") {
                                (StatusCode::NOT_FOUND, b"body")
                            } else {
                                (StatusCode::OK, b"body")
                            };
                        let mut response = Response::new(Full::new(Bytes::from_static(body)));
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
            package: Some(package.to_owned()),
            proxy_port: port,
            tarball: tarball.map(str::to_owned),
            purl: None,
        }
    }

    fn cli_purl(purl: &str, port: u16) -> Cli {
        Cli {
            package: None,
            proxy_port: port,
            tarball: None,
            purl: Some(purl.to_owned()),
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
        assert_eq!(parsed.package.as_deref(), Some("lodash"));
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
        // Neither a package nor a purl is provided.
        assert!(Cli::try_parse_from(["npm-fake"]).is_err());
    }

    #[test]
    fn purl_alone_is_accepted() {
        let parsed = Cli::try_parse_from(["npm-fake", "--purl", "pkg:npm/lodash@4.17.21"]).unwrap();
        assert_eq!(parsed.purl.as_deref(), Some("pkg:npm/lodash@4.17.21"));
        assert!(parsed.package.is_none());
    }

    #[test]
    fn purl_conflicts_with_package() {
        let result = Cli::try_parse_from(["npm-fake", "lodash", "--purl", "pkg:npm/lodash@1.0.0"]);
        assert!(result.is_err());
    }

    #[test]
    fn purl_conflicts_with_tarball() {
        let result = Cli::try_parse_from([
            "npm-fake",
            "--purl",
            "pkg:npm/lodash@1.0.0",
            "--tarball",
            "1.0.0",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_npm_purl_unscoped_with_version() {
        assert_eq!(
            parse_npm_purl("pkg:npm/lodash@4.17.21"),
            Some(("lodash".to_owned(), Some("4.17.21".to_owned())))
        );
    }

    #[test]
    fn parse_npm_purl_unscoped_without_version() {
        assert_eq!(
            parse_npm_purl("pkg:npm/lodash"),
            Some(("lodash".to_owned(), None))
        );
    }

    #[test]
    fn parse_npm_purl_scoped_with_version() {
        assert_eq!(
            parse_npm_purl("pkg:npm/@babel/core@7.0.0"),
            Some(("@babel/core".to_owned(), Some("7.0.0".to_owned())))
        );
    }

    #[test]
    fn parse_npm_purl_scoped_without_version() {
        assert_eq!(
            parse_npm_purl("pkg:npm/@types/node"),
            Some(("@types/node".to_owned(), None))
        );
    }

    #[test]
    fn parse_npm_purl_strips_qualifiers() {
        assert_eq!(
            parse_npm_purl("pkg:npm/lodash@4.17.21?arch=x64#sub"),
            Some(("lodash".to_owned(), Some("4.17.21".to_owned())))
        );
    }

    #[test]
    fn parse_npm_purl_rejects_non_npm() {
        assert!(parse_npm_purl("pkg:pypi/requests@2.0.0").is_none());
    }

    #[test]
    fn parse_npm_purl_rejects_empty_name() {
        assert!(parse_npm_purl("pkg:npm/").is_none());
    }

    #[test]
    fn parse_npm_purl_rejects_trailing_at() {
        assert!(parse_npm_purl("pkg:npm/lodash@").is_none());
    }

    #[test]
    fn resolve_target_from_purl() {
        let target = resolve_target(&cli_purl("pkg:npm/lodash@4.17.21", 4873)).unwrap();
        assert_eq!(target, ("lodash".to_owned(), Some("4.17.21".to_owned())));
    }

    #[test]
    fn resolve_target_from_invalid_purl_is_error() {
        assert!(resolve_target(&cli_purl("not-a-purl", 4873)).is_err());
    }

    #[test]
    fn resolve_target_from_package_and_tarball() {
        let target = resolve_target(&cli("lodash", 4873, Some("4.17.21"))).unwrap();
        assert_eq!(target, ("lodash".to_owned(), Some("4.17.21".to_owned())));
    }

    #[test]
    fn resolve_target_errors_without_package_or_purl() {
        let empty = Cli {
            package: None,
            proxy_port: 4873,
            tarball: None,
            purl: None,
        };
        assert!(resolve_target(&empty).is_err());
    }

    #[tokio::test]
    async fn run_fetches_via_purl() {
        let port = spawn_stub().await;
        assert!(run(cli_purl("pkg:npm/lodash@4.17.21", port)).await.is_ok());
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
    async fn failure_includes_response_body_reason() {
        let port = spawn_stub().await;
        let client = reqwest::Client::new();
        let url = format!("http://localhost:{port}/blocked-pkg");

        let err = fetch(&client, &url, "metadata").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "metadata request failed with status 403 Forbidden: package is blocked (malware)"
        );
    }

    #[tokio::test]
    async fn failure_with_empty_body_reports_only_status() {
        let port = spawn_stub().await;
        let client = reqwest::Client::new();
        let url = format!("http://localhost:{port}/noreason");

        let err = fetch(&client, &url, "metadata").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "metadata request failed with status 500 Internal Server Error"
        );
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
