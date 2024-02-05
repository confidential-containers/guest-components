# Attestation Agent

Attestation Agent (AA for short) is a service function set for attestation procedure
in Confidential Containers. It provides kinds of service APIs related to attestation.


Current consumers of AA include: 

- [ocicrypt-rs](../ocicrypt-rs)
- [image-rs](../image-rs)

## Components

The main body of AA is a rust library crate, which contains KBC modules used to communicate
with various KBS. In addition, this project also provides a gRPC service application, 
which allows callers to call the services provided by AA through gRPC.

## Library crate

Import AA in `Cargo.toml` of your project with all platform supported:

```toml
attestation-agent = { git = "https://github.com/confidential-containers/guest-components", features = ["all-attesters"] }
```

**Note**: When the version is stable, we will release AA on https://crate.io.

## gRPC Application

Here are the steps of building and running gRPC application of AA:

### Build

Build and install with default KBC modules:

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/attestation-agent
make && make install
```

or explicitly specify the platform it supports. Taking `tdx` as example:

```shell
make ATTESTER=tdx-attester
```

with no platform supprted
```shell
make ATTESTER=none
```

with all platforms supprted
```shell
make ATTESTER=all-attesters
```

#### Musl 

To build and install with musl, just run:
```shell
make LIBC=musl && make install
```

#### Openssl support

To build and install with openssl support (which is helpful in specific machines like `s390x`)
```
make OPENSSL=1 && make install
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
| sgx-attester        | Intel SGX DCAP              |
| snp-attester        | AMD SEV-SNP                 |
| az-snp-vtpm-attester| Azure SEV-SNP CVM           |
| az-tdx-vtpm-attester| Azure TDX CVM               |
| cca-attester        | Arm Confidential Compute Architecture (CCA)  |

To build AA with all available attesters and install, use
```shell
make ATTESTER=all-attesters && make install
```
