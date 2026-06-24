# package-chain-gate

A gate for detecting supply-chain risks — malware, typosquatting, and dependency
confusion — in package dependencies.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.94 or newer.

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` will select the
correct version automatically.

## Build

```sh
# Debug build
cargo build

# Optimized release build
cargo build --release
```

## Run

`package-chain-gate` listens for npm package manager proxy requests on a port,
screening packages before forwarding to the npm registry. The listening port is
configured with the optional `--proxy-port` option, which defaults to `4873`.

```sh
# Run via cargo (listens on the default port 4873)
cargo run

# Specify a custom port
cargo run -- --proxy-port 8080

# Load package vulnerability data for lookups
cargo run -- --package-config package_data.yaml

# Or run the compiled binary directly
./target/debug/package-chain-gate --proxy-port 4873
```

The optional `--package-config <PATH>` option loads a YAML file of known
vulnerable packages into an in-memory model keyed by purl (see
[Configuration](#configuration)).

Point npm at the gate by setting its registry to the listening address:

```sh
npm config set registry http://localhost:4873/
```

## Testing with `npm-fake`

This project ships a second binary, `npm-fake`, that issues the same HTTP
requests the real `npm` CLI makes when fetching a package (matching request
paths, `User-Agent`, and `Accept` headers), directed at the proxy's port. It
lets you exercise the proxy without installing or configuring npm.

```sh
# Start the proxy in one terminal
cargo run --bin package-chain-gate -- --proxy-port 4873

# In another terminal, fetch package metadata through the proxy
cargo run --bin npm-fake -- lodash

# Fetch metadata and a specific tarball version
cargo run --bin npm-fake -- lodash --tarball 4.17.21

# Scoped packages and a custom proxy port
cargo run --bin npm-fake -- @types/node --proxy-port 8080

# if you built it, run npm-fake with a purl
# this gets blocked with the example package_data.yaml (malware)
./target/debug/npm-fake --purl pkg:npm/lodash@4.17.21
# this works with package_data.yaml
./target/debug/npm-fake --purl pkg:npm/react@19.2.7
```

## MCP server

`--mcp-port <PORT>` additionally starts an [MCP](https://modelcontextprotocol.io)
server, backed by the same package data. It runs **alongside** the proxy (which
keeps listening on `--proxy-port`); the two are independent listeners:

```sh
# Proxy on 4873 AND MCP server on 8090
package-chain-gate --mcp-port 8090 --package-config package_data.yaml
```

It exposes one tool, **`package_check`**, which takes an `ecosystem` (e.g.
`npm`), `name` (e.g. `react`), and `version` (e.g. `19.2.7`). It builds the purl
`pkg:<ecosystem>/<name>@<version>` and looks it up in the package data:

- If the package is listed, the tool reports that it **must not be used** and
  names the vulnerabilities (e.g. `malware`).
- Otherwise it reports that the package appears safe to add.

The tool's description instructs clients to always call `package_check` before
adding a dependency or changing a version.

### Connecting

The server speaks the MCP **Streamable HTTP** transport over **plain HTTP** (no
TLS). Point your MCP client at:

```
http://127.0.0.1:8090
```

> ⚠️ Use `http://`, not `https://`. The server does not serve TLS, so an
> `https://` URL fails with a connection error.

Transport details:

- Clients **POST** JSON-RPC messages to the URL; requests receive a JSON
  response, notifications receive `202 Accepted`.
- The server does not offer a server-to-client SSE stream, so a `GET` to the
  endpoint returns `405 Method Not Allowed` (expected for this transport).
- The server is stateless — it does not issue an `Mcp-Session-Id`.

With the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```sh
npx @modelcontextprotocol/inspector
# Transport: Streamable HTTP    URL: http://127.0.0.1:8090
```

Or exercise it directly with `curl`:

```sh
curl -s http://127.0.0.1:8090 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"package_check","arguments":{"ecosystem":"npm","name":"react","version":"18.3.1"}}}'
```

## How it works

The gate runs as an HTTP reverse proxy in front of the public npm registry
(`https://registry.npmjs.org`). For each request it derives the package's purl
from the request path and looks it up in the loaded package data:

- If the purl is found, the package is **blocked**: the request is not forwarded,
  and the gate replies `403 Forbidden` with a body naming the package and its
  vulnerabilities (e.g. `malware`, `typosquatting`, `dependency_confusion`).
- Otherwise the request is forwarded upstream with its path and query preserved,
  and the registry's response is relayed back to the client.

Because the purl includes a version, blocking applies to versioned tarball
requests (`/lodash/-/lodash-4.17.21.tgz` → `pkg:npm/lodash@4.17.21`). Metadata
requests carry no version and are forwarded. When no `--package-config` is
given, the package data is empty and every request is forwarded.

## Test

```sh
# Run the test suite
cargo test
```

## Code coverage

Coverage is generated with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov).
Install it (and the required toolchain component) once:

```sh
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
```

Then generate a report:

```sh
# Per-file summary in the terminal
cargo llvm-cov --summary-only

# Full line-by-line report in the terminal
cargo llvm-cov

# HTML report (written to target/llvm-cov/html/index.html)
cargo llvm-cov --html

# lcov.info for CI or editor integrations
cargo llvm-cov --lcov --output-path lcov.info
```

> **Homebrew Rust note.** If your `rustc`/`cargo` come from Homebrew, they ship
> without `llvm-tools`, and `cargo llvm-cov` fails with *"failed to find
> llvm-tools-preview"*. Point it at the rustup toolchain's copies by exporting
> `LLVM_COV` and `LLVM_PROFDATA` (add to your shell profile to make it permanent):
>
> ```sh
> tools="$(rustup run 1.94 rustc --print target-libdir)/../bin"
> export LLVM_COV="$tools/llvm-cov"
> export LLVM_PROFDATA="$tools/llvm-profdata"
> ```
>
> Alternatively, run the command through the pinned toolchain directly:
> `rustup run 1.94 cargo llvm-cov --summary-only`.

## Linting & formatting

```sh
# Format the code
cargo fmt

# Check formatting without modifying files
cargo fmt --check

# Run the linter
cargo clippy
```

## Configuration

The `--package-config` file lists known vulnerable packages. Each package is
identified by its [purl](https://github.com/package-url/purl-spec) and mapped to
one or more vulnerability types (`malware`, `typosquatting`,
`dependency_confusion`). See [`package_data.yaml`](package_data.yaml) for a
complete example:

```yaml
packages:
  - pkg:npm/axios@1.9.3:
    - malware
    - dependency_confusion
  - pkg:npm/lodash@4.17.21:
    - malware
```

On startup the file is parsed into an in-memory model that supports lookups by
purl, which the proxy uses to block requests for known-vulnerable packages (see
[How it works](#how-it-works)).

## Updating package data

`--update-package` refreshes the local package-data file from the latest
[release](https://github.com/stlef14-security/package-data/releases/latest),
then exits without starting the proxy:

```sh
# Updates ./package_data.yaml
package-chain-gate --update-package

# Update a file at a specific path
package-chain-gate --update-package --package-config /etc/pcg/package_data.yaml
```

The update is version-aware and integrity-checked:

1. The latest release's version (tag) is compared with the locally cached
   version (recorded in a `<file>.version` sidecar). If they match, nothing is
   downloaded.
2. Otherwise the release's `package_data.yaml` and `package_data.yaml.sha256`
   assets are downloaded; the file's sha256 is computed and compared with the
   published checksum.
3. On a match the local file is replaced atomically and the version is recorded;
   on a mismatch the update is aborted with an error and the existing file is
   left untouched.


