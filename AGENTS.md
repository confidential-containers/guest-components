# Agents Guide — guest-components

The repo is a Rust workspace providing tools and components for use in confidential guests TEEs
(Trusted Execution Environments). Guest Components provide helpers for generating attestation evidence
from the TEE hardware and initialiazing a secret retrieval process, that can be provided to
confidential workloads. It's part of the [Confidential Containers](https://github.com/confidential-containers)
project and consumed by kata-containers or cloud-api-adaptor.

## Build

This is a Rust workspace (resolver v2) pinned to toolchain **1.90.0** (see `rust-toolchain.toml`).

```bash
# Build all workspace members (default features)
cargo build

# Build for a specific TEE platform via Makefile (cross-compiles to musl by default)
make build TEE_PLATFORM=none          # non-confidential
make build TEE_PLATFORM=az-cvm-vtpm   # Azure vTPM based attestation (TDX or SEV-SNP)
make build TEE_PLATFORM=tdx           # Intel TDX
make build TEE_PLATFORM=snp           # AMD SEV-SNP
make build TEE_PLATFORM=all           # all platforms

# Rebuild ttrpc/gRPC protobuf code (requires protoc)
make build-protos
```

## Test

```bash
# Run all tests for a single crate
cargo test -p attestation-agent
cargo test -p confidential-data-hub
cargo test -p image-rs
cargo test -p ocicrypt-rs

# Run a single test by name
cargo test -p image-rs -- test_name

# Many tests require specific features to compile
cargo test -p image-rs --features kata-cc-rustls-tls
cargo test -p confidential-data-hub --features kbs,aliyun,sev,bin
cargo test -p attestation-agent --features all-attesters,kbs,coco_as

# Integration tests often need serial execution
cargo test --test signature_verification -- --test-threads=1
```

Most integration tests require root privileges, running CDH/KBS services, and pre-installed test fixtures (GPG keys, offline-fs-kbc resources).

## Lint

```bash
cargo fmt --check
cargo clippy -- -D warnings

# Clippy with features (CI validates multiple feature combinations)
cargo clippy -p image-rs --features kata-cc-rustls-tls -- -D warnings
```

Pre-commit hooks run gitleaks, shellcheck, trailing-whitespace, and end-of-file-fixer.

## Architecture

### Components

| Component | Crate path | Role |
|-----------|-----------|------|
| **Attestation Agent (AA)** | `attestation-agent/attestation-agent` | Generates attestation evidence and tokens for TEE platforms |
| **Confidential Data Hub (CDH)** | `confidential-data-hub/hub` | Central broker for secrets, sealed data, KMS, and image resources |
| **image-rs** | `image-rs` | OCI container image pulling, decryption, and signature verification |
| **ocicrypt-rs** | `ocicrypt-rs` | OCI image encryption/decryption library |
| **api-server-rest** | `api-server-rest` | REST HTTP gateway that forwards to AA and CDH via ttrpc |
| **protos** | `protos` | Shared protobuf definitions for ttrpc and gRPC interfaces |

The sum of the above components is called "guest-components", the consuming project takes care of orchestration them in the correct order (AA first, then CDH, then ASR) and providing the necessary configuration.

### Communication

Components communicate over **ttrpc** (protobuf over Unix sockets, default) or **gRPC** (protobuf over HTTP/2, alternative). Each service (AA, CDH) builds as either `ttrpc-aa`/`grpc-aa` or `ttrpc-cdh`/`grpc-cdh`. The `api-server-rest` exposes a REST API and forwards to AA+CDH via ttrpc.

Data flow: `REST API → ttrpc → AA (attestation) + CDH (secrets/images) → image-rs (decryption with keys from CDH)`

### Feature flags

Feature flags are heavily used to control platform support, crypto backends, and protocol choices. Key categories:

- **TEE attesters** (AA): `tdx-attester`, `snp-attester`, `sgx-attester`, `se-attester`, `cca-attester`, `az-snp-vtpm-attester`, `az-tdx-vtpm-attester`, `all-attesters`
- **Crypto backends**: `encryption-ring` (default) vs `encryption-openssl`, `rust-crypto` vs `openssl`
- **Key wrapping** (image-rs/ocicrypt-rs): `keywrap-ttrpc`, `keywrap-grpc`, `keywrap-jwe`, `keywrap-keyprovider-cmd`
- **KMS providers** (CDH): `kbs`, `sev`, `aliyun`, `ehsm`
- **TLS**: `rustls-tls` (default) vs `native-tls`; preset features like `kata-cc-rustls-tls`
- **RPC protocol**: `ttrpc` (default), `grpc`

CI validates many feature combinations — when adding features or changing conditional compilation, test with multiple feature sets.


## Security Considerations

Remote attestation and secret delivery are security-sensitive operations. Changes to the
codebase should be made with due consideration of security implications, and new code should
be covered by comprehensive tests that validate security properties. We encourage coding
patterns that express invariant conditions in the type system, e.g. using a type state pattern
or newtypes to prevent misuse of APIs. Always consider the attack surface of new features and
strive to minimize it. This codebase is part of the Trusted Computing Base (TCB) of a confidential
workload, so we strive for extra caution and rigor in code quality and security hygiene. In general,
we want to avoid adding too much surface area in the TCB and avoid adding features that are not
strictly necessary for the core use cases.

## API Stability

The project is packaged and distributed downstream. Guest-Components do not provide
machine-enforcable schemas for all its payloads and protocols yet, but we strive to avoid breakage
for consumers when iterating. If it's unavoidable, we point it out expclicitly in commit messages,
so it can be tracked and aggregated in release notes.

## Relationship to Trustee

confidential-containers/trustee is a service counterpart to guest-components that is running
as a relying party and verifier in the RATS model outside of the TEE. It consumes the hardware
evidence and provides attestation tokens and secrets to a confidential guest. The two
repositories are developed and released in tandem, but they are decoupled and can be used
independently. guest-components's kbs-protocol crate is consumed by Trustee in the kbs-client
subproject.

## Sample Verifiers

It's unlikely that local development will happen in a TEE that is able to produce genuine
attestation evidence. Therefore there are "sample" and a "sample-device" attester/verifier
pairs that can be used as dummy stubs for testing end-to-end flow in local development and
testing. We should be aware that there is a risk that that these dummy implementations are
their evidence are accidentally used in production. We should make sure that in presence of
real TEE, we don't default or fallback to sample evidence.

## Conventions

### Commits

Commit messages have to contain a subsystem, indicated by a prefix plus colon, e.g.
"attester: fix hex encoding". This doesn't have to match strictly, but it should still
indicate a general area of the codebase that is being affected, e.g. "cdh:", "asr:", "ci:",
etc.

Commits should compile individually and contain atomic changes.

### PRs

PRs names have to contain a subsystem, indicated by a prefix plus colon, similar to commit
messages. We refrain from overloading the PR description with too much information, especially
excessive use of buzzwords and emojis is discouraged. We want to know _why_ a change is
being made, _how_ it is being made, and if applicable potential negative implications and
alternative options that have been considered.

### Misc

- **Error handling**: Domain-specific error enums via `thiserror` for public APIs, `anyhow::Result` for internal propagation. Both are used together throughout.
- **Async runtime**: Tokio with `#[tokio::main]`. Async trait methods use the `async-trait` crate.
- **Logging**: `tracing` crate (`info!`, `debug!`, `warn!`, `error!`). No `#[instrument]` usage.
- **Serialization**: JSON (`serde_json`) for configs/APIs, TOML for config files, protobuf for RPC.
- **Test attributes**: `#[tokio::test]` for async tests, `#[serial_test::serial]` to prevent parallel test interference, `rstest` for parameterized tests. Many tests are gated behind `#[cfg(feature = "...")]`.
- **Workspace dependencies**: All shared dependency versions are declared in the root `Cargo.toml` `[workspace.dependencies]`. Crate-level `Cargo.toml` files reference these with `dep.workspace = true`.
