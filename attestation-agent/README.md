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
provides a gRPC/ttrpc service application, which allows callers (such as
`confidential-data-hub`) to call the services provided by AA.

## Library crate

Import AA in `Cargo.toml` of your project with all platform supported:

```toml
attestation-agent = { git = "https://github.com/confidential-containers/guest-components", features = ["all-attesters"] }
```

**Note**: When the version is stable, we will release AA on https://crate.io.

## gRPC Application

Here are the steps of building and running gRPC application of AA:

### Build

Build and install with the default attester(s):

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/attestation-agent
make && make install
```

or explicitly specify the platform it supports. Taking `tdx` as example:

```shell
make ATTESTER=tdx-attester
```

with no platform supported
```shell
make ATTESTER=none
```

with all platforms supported
```shell
make ATTESTER=all-attesters
```

#### Musl 

To build and install with musl, just run:
```shell
make LIBC=musl && make install
```

### Run

For help information, just run:

```shell
attestation-agent --help
```

Start AA and specify the endpoint of AA's gRPC service:

```shell
attestation-agent --attestation_sock 127.0.0.1:50002
```

Or start AA with default address (127.0.0.1:50002)

```
attestation-agent
```

If you want to see the runtime log:
```
RUST_LOG=attestation_agent attestation-agent --attestation_sock 127.0.0.1:50002
```

### ttRPC

To build and install ttRPC Attestation Agent, just run:
```shell
make ttrpc=true && make install
```

ttRPC AA now only support Unix Socket, for example:

```shell
attestation-agent --attestation_sock unix:///tmp/attestation.sock
```

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
