# Attestation Agent

Attestation Agent (AA for short) is a service function set for attestation procedure
in Confidential Containers. It provides kinds of service APIs related to attestation.


Current consumers of AA include:

- [confidential-data-hub](../confidential-data-hub) (its `cc_kbc` KBC plugin uses AA to perform
  attestation and obtain a token; it then calls the KBS's `GetResource` API directly using that
  token)

AA no longer talks to `ocicrypt-rs`/`image-rs` directly for image decryption; that flow is now
handled by `confidential-data-hub`. See
[IMAGE_ENCRYPTION.md](docs/IMAGE_ENCRYPTION.md) and [IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
for details.

## Components

The main body of AA is a rust library crate, which contains attester modules used to generate
TEE evidence and negotiate an attestation token with a KBS. In addition, this project also
provides a gRPC/ttRPC service application, which allows callers (such as
`confidential-data-hub`) to call the services provided by AA.

## Library crate

Import AA in `Cargo.toml` of your project with all platform supported:

```toml
attestation-agent = { git = "https://github.com/confidential-containers/guest-components", features = ["all-attesters"] }
```

**Note**: When the version is stable, we will release AA on https://crate.io.

## Service Application

### ttRPC (default)

#### Build

Build and install with the default attester(s):

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/attestation-agent
make && make install
```

Or explicitly specify the platform. Taking `tdx` as an example:

```shell
make ATTESTER=tdx-attester
```

With no platform supported:

```shell
make ATTESTER=none
```

With the `all-attesters` feature set:

```shell
make ATTESTER=all-attesters
```

#### Musl

To build and install with musl:

```shell
make LIBC=musl && make install LIBC=musl
```

#### Run

For help information:

```shell
attestation-agent --help
```

ttRPC AA supports Unix sockets only, for example:

```shell
attestation-agent --attestation_sock unix:///tmp/attestation.sock
```

To see the runtime log:

```shell
RUST_LOG=attestation_agent attestation-agent --attestation_sock unix:///tmp/attestation.sock
```

### gRPC

To build and install the gRPC Attestation Agent:

```shell
make ttrpc=false && make install
```

To run with a TCP endpoint:

```shell
attestation-agent --attestation_sock 127.0.0.1:50002
```

### GetToken parameters

`GetToken` takes a `token_type` and a string map of extra parameters. Each token
type accepts a fixed set of keys. Any other key is rejected.

| Token type | Allowed parameters |
| ---------- | ------------------ |
| `kbs`      | none               |
| `coco_as`  | `nonce` or `runtime_data`, at most one |

- `nonce`: URL-safe base64 without padding. The decoded bytes are the evidence
  challenge.
- `runtime_data`: a string containing JSON text, not a nested JSON object.
  The evidence challenge is the SHA-384 digest of that JSON after RFC 8785
  canonicalization, which is how CoCo Attestation Service checks `structured`
  runtime data against report data. The parsed JSON is sent to the service as
  `runtime_data.structured`.

Omitting both `coco_as` parameters requests a token with an empty challenge and
no runtime data. Setting both is rejected.

### Supported Platforms

AA supports different kinds of hardware TEE attesters, now
| Attester name       |           Info              |
| ------------------- | --------------------------  |
| tdx-attester        | Intel TDX                   |
| tdx-attester-libtdx | Intel TDX (using libtdx-attest for certain non-upstream Linux `ioctl()`s). Disabled by default. |
| sgx-attester        | Intel SGX DCAP              |
| snp-attester        | AMD SEV-SNP                 |
| az-snp-vtpm-attester| Azure SEV-SNP CVM           |
| az-tdx-vtpm-attester| Azure TDX CVM               |
| cca-attester        | Arm Confidential Compute Architecture (CCA)  |
| se-attester         | IBM Secure Execution (SE)   |

To build AA with all available attesters and install, use
```shell
make ATTESTER=all-attesters && make install
```
