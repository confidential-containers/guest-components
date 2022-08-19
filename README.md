# Attestation Agent

Attestation Agent (AA for short) is a service function set for attestation procedure
in Confidential Containers. It provides kinds of service APIs that need to make
requests to the Relying Party (Key Broker Service) in Confidential Containers,
and performs an attestation and establishes connection between the Key Broker Client (KBC)
and corresponding KBS, so as to obtain the trusted services or resources of KBS.


Current consumers of AA include: 

- [ocicrypt-rs](https://github.com/confidential-containers/ocicrypt-rs)
- [image-rs](https://github.com/confidential-containers/image-rs)

## Components

The main body of AA is a rust library crate, which contains KBC modules used to communicate
with various KBS. In addition, this project also provides a gRPC service application, 
which allows callers to call the services provided by AA through gRPC.

## Library crate

Import AA in `Cargo.toml` of your project with specific KBC(s):

```toml
attestation-agent = { git = "https://github.com/confidential-containers/attestation-agent", features = ["sample_kbc"] }
```

**Note**: When the version is stable, we will release AA on https://crate.io.

## gRPC Application

Here are the steps of building and running gRPC application of AA:

### Build

Build and install with default KBC modules:

```shell
git clone https://github.com/containers/attestation-agent
cd attestation-agent
make && make install
```

or explicitly specify the KBS modules it contains. Taking `sample_kbc` as example:

```shell
make KBC=sample_kbc
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
attestation-agent --keyprovider_sock 127.0.0.1:50000 --getresource_sock 127.0.0.1:50001
```

Or start AA with default keyprovider address (127.0.0.1:50000) and default getresource address (127.0.0.1:50001):

```
attestation-agent
```

If you want to see the runtime log:
```
RUST_LOG=attestation_agent attestation-agent --keyprovider_sock 127.0.0.1:50000 --getresource_sock 127.0.0.1:50001
```

## Supported KBC modules

AA provides a flexible KBC module mechanism to support different KBS protocols required to make the communication between KBC and KBS. If the KBC modules currently supported by AA cannot meet your use requirement (e.g, need to use a new KBS protocol), you can write a new KBC module complying with the KBC development [GUIDE](docs/kbc_module_development_guide.md). Welcome to contribute new KBC module to this project!

List of supported KBC modules: 

| KBC module name    | README                                                              | KBS protocol | Maintainer                |
| ------------------ | ------------------------------------------------------------------- | ------------ | ------------------------- |
| sample_kbc         | Null                                                                | Null         | Attestation Agent Authors |
| offline_fs_kbc     | [Offline file system KBC](src/kbc_modules/offline_fs_kbc/README.md) | Null         | IBM                       |
| eaa_kbc            | [EAA KBC](src/kbc_modules/eaa_kbc/README.md)                        | EAA protocol | Alibaba Cloud             |
| offline_sev_kbc    | [Offline SEV KBC](src/kbc_modules/offline_sev_kbc/README.md)        | Null         | IBM                       |
| online_sev_kbc     | [Online SEV KBC](src/kbc_modules/online_sev_kbc/README.md)          | simple-kbs   | IBM                       |


## Tools

- [Sample Keyprovider](./sample_keyprovider): A simple tool for encrypting container images with skopeo, please refer to its [README](./sample_keyprovider/README.md).

