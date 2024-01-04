# Attestation Agent

Attestation Agent (AA for short) is a service function set for attestation procedure
in Confidential Containers.

## Components

The main body of AA is a rust library crate.
In addition, this project also provides a gRPC service application, 
which allows callers to call the services provided by AA through gRPC.

## Library crate

Import AA in `Cargo.toml` of your project:

```toml
attestation-agent = { git = "https://github.com/confidential-containers/guest-components" }
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

For details of building parameters, run:

```
make help
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

Or start AA with default address (127.0.0.1:50002):

```
attestation-agent
```

If you want to see the runtime log:
```
RUST_LOG=attestation_agent attestation-agent
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

