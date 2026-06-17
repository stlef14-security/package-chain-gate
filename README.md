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

```sh
# Run via cargo
cargo run

# Or run the compiled binary directly
./target/debug/package-chain-gate
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
