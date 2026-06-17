use std::net::{Ipv4Addr, SocketAddr};

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};

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
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    let listener = TcpListener::bind(listen_addr(cli.proxy_port)).await?;
    println!(
        "package-chain-gate listening for npm proxy requests on {}",
        listener.local_addr()?
    );

    serve(listener).await
}

/// Runs the accept loop, handling each accepted connection on its own task.
async fn serve(listener: TcpListener) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (socket, peer) = listener.accept().await?;
        println!("accepted connection from {peer}");

        // Each connection is handled independently so a slow client can't block
        // the accept loop.
        tokio::spawn(async move {
            handle_connection(socket).await;
        });
    }
}

/// Handles a single proxied npm client connection.
///
/// TODO: parse the incoming npm request, screen the requested package for
/// supply-chain risks (malware, typosquatting, dependency confusion), and
/// forward allowed requests to the upstream npm registry.
#[allow(
    clippy::unused_async,
    reason = "async signature reserved for upcoming proxy logic"
)]
async fn handle_connection(_socket: TcpStream) {
    // Placeholder: connection handling is not implemented yet.
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn serve_accepts_incoming_connections() {
        // Bind to port 0 so the OS assigns a free ephemeral port.
        let listener = TcpListener::bind(listen_addr(0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(serve(listener));

        // A client connection should be accepted without the accept loop erroring.
        let client = TcpStream::connect(addr).await;
        assert!(client.is_ok());

        // The server runs an infinite accept loop, so stop it explicitly.
        server.abort();
    }
}
