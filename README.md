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

## Test

```sh
# Run the test suite
cargo test
```

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
