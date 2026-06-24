use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

use crate::package_data::PackageData;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// MCP protocol version advertised when a client does not request one.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Server name reported during initialization.
const SERVER_NAME: &str = "package-chain-gate";

/// Runs the MCP server accept loop, serving the Streamable HTTP transport.
///
/// # Errors
/// Returns an error if accepting a connection fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    data: Arc<PackageData>,
) -> Result<(), BoxError> {
    loop {
        let (socket, _) = listener.accept().await?;
        let data = Arc::clone(&data);
        tokio::spawn(async move {
            let io = TokioIo::new(socket);
            let service = service_fn(move |req| handle_http(req, Arc::clone(&data)));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

/// Handles a single HTTP request to the MCP endpoint. Clients POST a JSON-RPC
/// message; requests get a JSON response, notifications get `202 Accepted`.
async fn handle_http(
    req: Request<Incoming>,
    data: Arc<PackageData>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    if req.method() != Method::POST {
        // Only client-to-server POST is supported; no server-initiated SSE stream.
        return Ok(status_response(StatusCode::METHOD_NOT_ALLOWED));
    }

    let body = req.into_body().collect().await?.to_bytes();
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return Ok(json_response(StatusCode::BAD_REQUEST, &parse_error()));
    };

    match handle_message(&message, &data) {
        Some(response) => Ok(json_response(StatusCode::OK, &response)),
        None => Ok(status_response(StatusCode::ACCEPTED)),
    }
}

/// Dispatches a JSON-RPC message, returning a response for requests and `None`
/// for notifications (or any message without a method).
#[must_use]
pub fn handle_message(message: &Value, data: &PackageData) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str)?;
    // Notifications carry no `id` and receive no response.
    let id = message.get("id")?;
    Some(dispatch(method, message, id, data))
}

fn dispatch(method: &str, message: &Value, id: &Value, data: &PackageData) -> Value {
    match method {
        "initialize" => success(id, &initialize_result(message)),
        "ping" => success(id, &json!({})),
        "tools/list" => success(id, &json!({ "tools": [tool_definition()] })),
        "tools/call" => call_tool(message.get("params"), id, data),
        _ => error(id, -32601, &format!("method not found: {method}")),
    }
}

fn initialize_result(message: &Value) -> Value {
    let protocol = message
        .get("params")
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(MCP_PROTOCOL_VERSION);

    json!({
        "protocolVersion": protocol,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
    })
}

/// The `package_check` tool definition, with strong language directing clients to
/// always check a package before adding or upgrading it.
fn tool_definition() -> Value {
    json!({
        "name": "package_check",
        "description": "Check whether a package version is safe to add to a project by looking \
            it up in the supply-chain vulnerability database (malware, typosquatting, dependency \
            confusion). YOU MUST ALWAYS call package_check BEFORE adding a new dependency or \
            changing the version of an existing dependency. NEVER add or upgrade a package \
            without first confirming with package_check that it is safe to use.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": { "type": "string", "description": "Package ecosystem, e.g. \"npm\"." },
                "name": { "type": "string", "description": "Package name, e.g. \"react\"." },
                "version": { "type": "string", "description": "Package version, e.g. \"19.2.7\"." }
            },
            "required": ["ecosystem", "name", "version"]
        }
    })
}

fn call_tool(params: Option<&Value>, id: &Value, data: &PackageData) -> Value {
    let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
    if name != Some("package_check") {
        return error(
            id,
            -32602,
            &format!("unknown tool: {}", name.unwrap_or("<none>")),
        );
    }

    let arguments = params.and_then(|p| p.get("arguments"));
    let ecosystem = arguments
        .and_then(|a| a.get("ecosystem"))
        .and_then(Value::as_str);
    let package = arguments
        .and_then(|a| a.get("name"))
        .and_then(Value::as_str);
    let version = arguments
        .and_then(|a| a.get("version"))
        .and_then(Value::as_str);

    let (Some(ecosystem), Some(package), Some(version)) = (ecosystem, package, version) else {
        return error(
            id,
            -32602,
            "package_check requires `ecosystem`, `name`, and `version`",
        );
    };

    let purl = make_purl(ecosystem, package, version);
    let text = check_message(&purl, data);
    success(
        id,
        &json!({ "content": [{ "type": "text", "text": text }] }),
    )
}

/// Builds a purl from its ecosystem, name, and version components.
fn make_purl(ecosystem: &str, name: &str, version: &str) -> String {
    format!("pkg:{ecosystem}/{name}@{version}")
}

/// Produces the verdict text for a package check.
fn check_message(purl: &str, data: &PackageData) -> String {
    match data.lookup(purl) {
        Some(vulnerabilities) => {
            let mut labels: Vec<&str> = vulnerabilities.iter().map(|v| v.label()).collect();
            labels.sort_unstable();
            format!(
                "DO NOT add or use {purl}. It is flagged in the supply-chain database for: {}. \
                 Choose a safe alternative package or version.",
                labels.join(", ")
            )
        }
        None => format!(
            "{purl} is not listed in the supply-chain vulnerability database and appears safe \
             to add."
        ),
    }
}

fn success(id: &Value, result: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn parse_error() -> Value {
    json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } })
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn status_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;

    fn vulnerable_data() -> PackageData {
        PackageData::from_yaml(
            "packages:\n  - pkg:npm/react@1.19.7:\n    - malware\n    - typosquatting\n",
        )
        .unwrap()
    }

    fn call_request(arguments: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "package_check", "arguments": arguments }
        })
    }

    #[test]
    fn make_purl_builds_purl_including_scoped_names() {
        assert_eq!(make_purl("npm", "react", "1.19.7"), "pkg:npm/react@1.19.7");
        assert_eq!(
            make_purl("npm", "@babel/core", "7.0.0"),
            "pkg:npm/@babel/core@7.0.0"
        );
    }

    #[test]
    fn initialize_reports_server_info() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        });
        let response = handle_message(&request, &PackageData::default()).unwrap();

        assert_eq!(
            response["result"]["serverInfo"]["name"],
            "package-chain-gate"
        );
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn initialize_defaults_protocol_version() {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });
        let response = handle_message(&request, &PackageData::default()).unwrap();
        assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    }

    #[test]
    fn tools_list_advertises_package_check_with_strong_language() {
        let request = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let response = handle_message(&request, &PackageData::default()).unwrap();

        let tool = &response["result"]["tools"][0];
        assert_eq!(tool["name"], "package_check");
        let description = tool["description"].as_str().unwrap();
        assert!(description.contains("ALWAYS"));
        assert!(description.contains("NEVER"));
        let required = tool["inputSchema"]["required"].as_array().unwrap();
        assert_eq!(required.len(), 3);
    }

    #[test]
    fn package_check_reports_safe_for_unknown_package() {
        let request = call_request(&json!({
            "ecosystem": "npm", "name": "leftpad", "version": "1.0.0"
        }));
        let response = handle_message(&request, &vulnerable_data()).unwrap();

        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("appears safe"));
        assert!(text.contains("pkg:npm/leftpad@1.0.0"));
    }

    #[test]
    fn package_check_blocks_known_vulnerable_package() {
        let request = call_request(&json!({
            "ecosystem": "npm", "name": "react", "version": "1.19.7"
        }));
        let response = handle_message(&request, &vulnerable_data()).unwrap();

        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("DO NOT"));
        // Labels are sorted, so order is deterministic.
        assert!(text.contains("malware, typosquatting"));
        assert!(text.contains("pkg:npm/react@1.19.7"));
    }

    #[test]
    fn tools_call_unknown_tool_is_an_error() {
        let request = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "other_tool", "arguments": {} }
        });
        let response = handle_message(&request, &PackageData::default()).unwrap();
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn package_check_missing_arguments_is_an_error() {
        let request = call_request(&json!({ "ecosystem": "npm", "name": "react" }));
        let response = handle_message(&request, &PackageData::default()).unwrap();
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let request = json!({ "jsonrpc": "2.0", "id": 4, "method": "no/such/method" });
        let response = handle_message(&request, &PackageData::default()).unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn ping_returns_empty_result() {
        let request = json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" });
        let response = handle_message(&request, &PackageData::default()).unwrap();
        assert!(response["result"].is_object());
    }

    #[test]
    fn notification_without_id_has_no_response() {
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_message(&notification, &PackageData::default()).is_none());
    }

    #[test]
    fn message_without_method_is_ignored() {
        let response = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        assert!(handle_message(&response, &PackageData::default()).is_none());
    }

    async fn spawn_mcp(data: PackageData) -> String {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(data)));
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn http_post_request_returns_json_response() {
        let base = spawn_mcp(PackageData::default()).await;
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });

        let response = reqwest::Client::new()
            .post(&base)
            .header("content-type", "application/json")
            .body(request.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(body["result"]["serverInfo"]["name"], "package-chain-gate");
    }

    #[tokio::test]
    async fn http_post_notification_is_accepted() {
        let base = spawn_mcp(PackageData::default()).await;
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });

        let response = reqwest::Client::new()
            .post(&base)
            .body(notification.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 202);
    }

    #[tokio::test]
    async fn http_get_is_method_not_allowed() {
        let base = spawn_mcp(PackageData::default()).await;
        let response = reqwest::get(&base).await.unwrap();
        assert_eq!(response.status(), 405);
    }

    #[tokio::test]
    async fn http_post_invalid_json_is_bad_request() {
        let base = spawn_mcp(PackageData::default()).await;
        let response = reqwest::Client::new()
            .post(&base)
            .body("{ not json")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
    }
}
