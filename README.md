# Attestation Agent

Attestation Agent (AA for short) is an user space service for attestation procedure. In Kata Confidential Containers (Kata CC for short), AA implements the WrapKey API defined by keyprovider protocol, which is responsible for performing attestation and obtaining the Key Encryption Key (KEK for short) from Key Broker Service (KBS for short) , or requesting KBS to decrypt the encrypted payload stored in the image layer annotation.

Current consumers of AA include: 

- [ocicrypt-rs](https://github.com/containers/ocicrypt-rs)
- [ocicrypt](https://github.com/containers/ocicrypt)

## Usage

Here are the steps of building and running AA:

### Build

Build AA with all KBC modules:

```shell
git glone https://github.com/containers/attestation-agent
cd attestation-agent
cargo build --release
```

or explicitly specify the KBS modules it contains. Taking `sample_kbc` as example:

```shell
cargo build --release --no-default-features --features sample_kbc
```

### Run

For help information, just run:

```shell
cd target/release
./attestation-agent --help
```

Start AA and use grpc_sock parameter to specify the endpoint of AA's keyprovider service, e.g, listen on local 47777 port:

```shell
./attestation-agent --grpc_sock 127.0.0.1:47777
```

## Supported KBC modules

AA provides a flexible KBC module mechanism to support different KBS protocols required to make the communication between KBC and KBS. If the KBC modules currently supported by AA cannot meet your use requirement (e.g, need to use a new KBS protocol), you can write a new KBC module complying with the KBC development [GUIDE](docs/kbc_module_development_guide.md). Welcome to contribute new KBC module to this project!

List of supported KBC modules: 

| KBC module name | README | KBS protocol | Maintainer                |
| --------------- | ------ | ------------ | ------------------------- |
| sample_kbc      | Null   | Null         | Attestation Agent Authors |

