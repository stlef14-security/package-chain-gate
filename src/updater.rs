use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// GitHub API endpoint for the latest `package-data` release.
pub const RELEASES_API: &str =
    "https://api.github.com/repos/stlef14-security/package-data/releases/latest";

/// Name of the data asset within a release.
const DATA_ASSET: &str = "package_data.yaml";
/// Name of the sha256 checksum asset within a release.
const SHA_ASSET: &str = "package_data.yaml.sha256";

/// Outcome of an update check.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The local copy already matches the latest release version.
    UpToDate { version: String },
    /// The local copy was replaced with the latest release version.
    Updated { version: String },
}

/// The subset of a GitHub release we care about.
#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

impl Release {
    fn asset_url(&self, name: &str) -> Option<&str> {
        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.browser_download_url.as_str())
    }
}

/// Updates the package-data file at `target` from the latest release.
///
/// Fetches the latest release metadata, and if its version differs from the
/// locally cached one, downloads the data and its sha256, verifies the checksum,
/// and atomically replaces `target` (recording the new version). When the
/// version already matches, nothing is downloaded.
///
/// # Errors
/// Returns an error if the release cannot be fetched, the expected assets are
/// missing, a download fails, or the downloaded file's sha256 does not match the
/// published checksum.
pub async fn update_package(
    client: &reqwest::Client,
    api_url: &str,
    target: &Path,
) -> Result<UpdateOutcome, BoxError> {
    let body = client
        .get(api_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let release: Release = serde_json::from_str(&body)?;

    if local_version(target).as_deref() == Some(release.tag_name.as_str()) {
        return Ok(UpdateOutcome::UpToDate {
            version: release.tag_name,
        });
    }

    let data_url = release
        .asset_url(DATA_ASSET)
        .ok_or_else(|| format!("release {} has no `{DATA_ASSET}` asset", release.tag_name))?;
    let sha_url = release
        .asset_url(SHA_ASSET)
        .ok_or_else(|| format!("release {} has no `{SHA_ASSET}` asset", release.tag_name))?;

    let data = client
        .get(data_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let sha_text = client
        .get(sha_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let expected = parse_sha256(&sha_text).ok_or("sha256 asset is empty")?;
    let computed = sha256_hex(&data);
    if computed != expected {
        return Err(format!(
            "sha256 mismatch for {DATA_ASSET}: expected {expected}, computed {computed}; \
             aborting update"
        )
        .into());
    }

    write_atomically(target, &data)?;
    std::fs::write(version_path(target), &release.tag_name)?;

    Ok(UpdateOutcome::Updated {
        version: release.tag_name,
    })
}

/// Path of the sidecar file that records the locally cached release version.
fn version_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_owned();
    name.push(".version");
    target.with_file_name(name)
}

/// Reads the locally cached release version, if recorded.
fn local_version(target: &Path) -> Option<String> {
    std::fs::read_to_string(version_path(target))
        .ok()
        .map(|contents| contents.trim().to_owned())
}

/// Extracts the hex digest from sha256 file contents. Accepts a bare digest,
/// `sha256sum` format (`<hex>  <filename>`), and an optional `sha256:` prefix.
fn parse_sha256(contents: &str) -> Option<String> {
    let token = contents.split_whitespace().next()?.to_ascii_lowercase();
    let hex = token.strip_prefix("sha256:").unwrap_or(&token);
    (!hex.is_empty()).then(|| hex.to_owned())
}

/// Computes the lowercase hex sha256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Writes `data` to `target` via a temporary file in the same directory, then
/// renames it into place so the replacement is atomic.
fn write_atomically(target: &Path, data: &[u8]) -> Result<(), BoxError> {
    let tmp = target.with_extension("tmp-download");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, target)?;
    Ok(())
}

/// A mock GitHub release server, shared by this module's and `main`'s tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    /// What a spawned mock release should serve. A `None` asset is omitted from
    /// the release, so its download URL is absent.
    pub struct ReleaseSpec {
        pub tag: String,
        pub data: Option<Vec<u8>>,
        pub sha: Option<String>,
    }

    /// Computes the lowercase hex sha256 of `data` (exposed for tests).
    pub fn sha256_hex(data: &[u8]) -> String {
        super::sha256_hex(data)
    }

    /// Spawns the mock server and returns its base URL. The latest-release
    /// endpoint is at `<base>/releases/latest`.
    pub async fn spawn_release_server(spec: ReleaseSpec) -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());

        let mut assets = Vec::new();
        if spec.data.is_some() {
            assets.push(serde_json::json!({
                "name": super::DATA_ASSET,
                "browser_download_url": format!("{base}/data"),
            }));
        }
        if spec.sha.is_some() {
            assets.push(serde_json::json!({
                "name": super::SHA_ASSET,
                "browser_download_url": format!("{base}/sha"),
            }));
        }
        let release_json =
            serde_json::json!({ "tag_name": spec.tag, "assets": assets }).to_string();

        let state = Arc::new((release_json, spec.data, spec.sha));

        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(socket);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move {
                            let (json, data, sha) = (&state.0, &state.1, &state.2);
                            let response = match req.uri().path() {
                                "/releases/latest" => {
                                    Response::new(Full::new(Bytes::from(json.clone())))
                                }
                                "/data" => Response::new(Full::new(Bytes::from(
                                    data.clone().unwrap_or_default(),
                                ))),
                                "/sha" => Response::new(Full::new(Bytes::from(
                                    sha.clone().unwrap_or_default(),
                                ))),
                                _ => {
                                    let mut response = Response::new(Full::new(Bytes::new()));
                                    *response.status_mut() = StatusCode::NOT_FOUND;
                                    response
                                }
                            };
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        base
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{ReleaseSpec, spawn_release_server};
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    /// sha256("package data") precomputed for assertions.
    const DATA: &[u8] = b"package data";
    fn data_sha() -> String {
        sha256_hex(DATA)
    }

    fn temp_target() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("pcg-upd-{}-{n}.yaml", std::process::id()))
    }

    fn cleanup(target: &Path) {
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(version_path(target));
        let _ = std::fs::remove_file(target.with_extension("tmp-download"));
    }

    #[test]
    fn sha256_hex_matches_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_sha256_reads_bare_and_sha256sum_formats() {
        assert_eq!(parse_sha256("ABCDEF\n").as_deref(), Some("abcdef"));
        assert_eq!(
            parse_sha256("abcdef  package_data.yaml\n").as_deref(),
            Some("abcdef")
        );
        // GitHub's release asset uses a `sha256:` prefix.
        assert_eq!(parse_sha256("sha256:ABCDEF").as_deref(), Some("abcdef"));
        assert!(parse_sha256("   ").is_none());
        assert!(parse_sha256("sha256:").is_none());
    }

    #[test]
    fn version_path_appends_suffix() {
        assert_eq!(
            version_path(Path::new("/tmp/package_data.yaml")),
            PathBuf::from("/tmp/package_data.yaml.version")
        );
    }

    #[test]
    fn local_version_reads_and_trims_or_none() {
        let target = temp_target();
        assert!(local_version(&target).is_none());

        std::fs::write(version_path(&target), "v1.2.3\n").unwrap();
        assert_eq!(local_version(&target).as_deref(), Some("v1.2.3"));

        cleanup(&target);
    }

    #[tokio::test]
    async fn downloads_and_replaces_when_no_local_version() {
        let target = temp_target();
        let base = spawn_release_server(ReleaseSpec {
            tag: "v2.0.0".to_owned(),
            data: Some(DATA.to_vec()),
            sha: Some(data_sha()),
        })
        .await;

        let outcome = update_package(
            &reqwest::Client::new(),
            &format!("{base}/releases/latest"),
            &target,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            UpdateOutcome::Updated {
                version: "v2.0.0".to_owned()
            }
        );
        assert_eq!(std::fs::read(&target).unwrap(), DATA);
        assert_eq!(local_version(&target).as_deref(), Some("v2.0.0"));

        cleanup(&target);
    }

    #[tokio::test]
    async fn does_nothing_when_version_matches() {
        let target = temp_target();
        std::fs::write(&target, b"old data").unwrap();
        std::fs::write(version_path(&target), "v2.0.0").unwrap();

        let base = spawn_release_server(ReleaseSpec {
            tag: "v2.0.0".to_owned(),
            data: Some(DATA.to_vec()),
            sha: Some(data_sha()),
        })
        .await;

        let outcome = update_package(
            &reqwest::Client::new(),
            &format!("{base}/releases/latest"),
            &target,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            UpdateOutcome::UpToDate {
                version: "v2.0.0".to_owned()
            }
        );
        // The existing file is untouched.
        assert_eq!(std::fs::read(&target).unwrap(), b"old data");

        cleanup(&target);
    }

    #[tokio::test]
    async fn aborts_and_keeps_file_on_sha_mismatch() {
        let target = temp_target();
        std::fs::write(&target, b"old data").unwrap();

        let base = spawn_release_server(ReleaseSpec {
            tag: "v3.0.0".to_owned(),
            data: Some(DATA.to_vec()),
            sha: Some("00deadbeef".to_owned()),
        })
        .await;

        let err = update_package(
            &reqwest::Client::new(),
            &format!("{base}/releases/latest"),
            &target,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("sha256 mismatch"));
        // The local file is not replaced.
        assert_eq!(std::fs::read(&target).unwrap(), b"old data");

        cleanup(&target);
    }

    #[tokio::test]
    async fn errors_when_data_asset_missing() {
        let target = temp_target();
        let base = spawn_release_server(ReleaseSpec {
            tag: "v1.0.0".to_owned(),
            data: None,
            sha: Some(data_sha()),
        })
        .await;

        let err = update_package(
            &reqwest::Client::new(),
            &format!("{base}/releases/latest"),
            &target,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("package_data.yaml` asset"));
        cleanup(&target);
    }

    #[tokio::test]
    async fn errors_when_sha_asset_missing() {
        let target = temp_target();
        let base = spawn_release_server(ReleaseSpec {
            tag: "v1.0.0".to_owned(),
            data: Some(DATA.to_vec()),
            sha: None,
        })
        .await;

        let err = update_package(
            &reqwest::Client::new(),
            &format!("{base}/releases/latest"),
            &target,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("package_data.yaml.sha256` asset"));
        cleanup(&target);
    }

    #[tokio::test]
    async fn errors_when_release_endpoint_missing() {
        let target = temp_target();
        let base = spawn_release_server(ReleaseSpec {
            tag: "v1.0.0".to_owned(),
            data: Some(DATA.to_vec()),
            sha: Some(data_sha()),
        })
        .await;

        // Point at a path the mock serves as 404.
        let result = update_package(
            &reqwest::Client::new(),
            &format!("{base}/no-such-release"),
            &target,
        )
        .await;

        assert!(result.is_err());
        cleanup(&target);
    }
}
