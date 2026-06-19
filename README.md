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
purl. (Acting on those lookups to block requests is a later step.)
