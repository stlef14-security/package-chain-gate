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

# Or run the compiled binary directly
./target/debug/package-chain-gate --proxy-port 4873
```

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
```

## How it works

The gate runs as an HTTP reverse proxy in front of the public npm registry
(`https://registry.npmjs.org`). Incoming requests (package metadata lookups,
tarball downloads, etc.) are forwarded upstream with their path and query
preserved, and the registry's response is relayed back to the client.

Supply-chain screening of the requested package (malware, typosquatting,
dependency confusion) is not yet implemented — every request is currently passed
through unchanged.

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

> If a Homebrew-installed Rust toolchain shadows `rustup` on your `PATH`, run the
> commands through the pinned toolchain instead, e.g.
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

See [`config.example.yaml`](config.example.yaml) for the expected configuration
format. Packages are identified using [purl](https://github.com/package-url/purl-spec)
identifiers (e.g. `pkg:npm/lodash@4.17.21`).
