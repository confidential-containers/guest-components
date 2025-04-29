# Confidential Data Hub

Confidential Data Hub (`CDH`) is a service running inside the guest to provide resource related
APIs.



### Build

Build and install with default features:

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/confidential-data-hub
make
```
This will build CDH with `RESOURCE_PROVIDER=kbs,sev` and `KMS_PROVIDER=aliyun,ehsm`

You can explicitly specify the confidential resource provider and KMS_PROVIDER plugin during the build.
For example if you only want to include `aliyun` KMS_PROVIDER: 

```shell
make KMS_PROVIDER=aliyun
```

If you don't want to include any KMS_PROVIDER(s) and want to use only `kbs` as the resource provider:
```shell
make RESOURCE_PROVIDER=kbs KMS_PROVIDER=none
```

If you don't want to include any RESOURCE_PROVIDER(s):
```shell
make RESOURCE_PROVIDER=none
```

The default CDH runs as a service daemon. If you want to build CDH to an one-shot binary (run once and exit), use flag `ONE_SHOT=true`
```shell
make ONE_SHOT=true
```

Please refer to [Supported Features](#supported-features) for the options.

### Supported Features

Confidential resource providers (flag `RESOURCE_PROVIDER`)

| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| kbs                 | For TDX/SNP/Azure-SNP-vTPM based on KBS Attestation Protocol       |
| sev                 | For SEV based on efi secret pre-attestation                        |

Note:
- If no `RESOURCE_PROVIDER` flag is given, then all the resource providers will be enabled by default

KMS_PROVIDER plugins (flag `KMS_PROVIDER`)

| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| aliyun              | Use aliyun KMS_PROVIDER suites to unseal secrets, etc.                      |
| ehsm(no longer maintained) | Use Intel eHSM KMS_PROVIDER suites to unseal secrets, etc.                  |

Note:
- If no `KMS_PROVIDER` flag is given, then all the KMS providers will be enabled by default.

RPC plugins (flag `RPC`)
| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| grpc                | Use grpc API to serve for requests (TCP/IP socket).                |
| ttrpc               | Use ttrpc API to serve for requests (Unix socket).                 |

### Configuration file

CDH will be launched by a configuration file by
```shell
confidential-data-hub -c <path-to-config>
```

Please see the example config file in [toml](./example.config.toml) or [json](./example.config.json) for more details.

However, if a file isn't passed with **-c** then it will search for configurations on the
following locations (in order):

* **/etc/confidential-data-hub.conf**
* **AA_KBC_PARAMS** environment variable
* **agent.aa_kbc_params** parameter from the Kernel command-line (`/proc/cmdline`)

There is a special case which is when running from [peer pods](https://github.com/confidential-containers/cloud-api-adaptor). It
will try to read from the kata-agent file (**/etc/agent-config.toml** or **KATA_AGENT_CONFIG_PATH** environment variable) prior
to looking for `aa_kbc_params`.

Finally on the abscence of a configuration, CDH will be configured with the `offline_fs_kbc` Key Broker Client (KBC).
### Client Tool

A client tool to interact with CDH is provided. 

#### ttRPC Client Tool

run the following to build
```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/confidential-data-hub/hub
cargo build --bin ttrpc-cdh-tool --features bin,ttrpc
cargo build --release --no-default-features --bin ttrpc-cdh-tool --features bin,ttrpc --target aarch64-unknown-linux-musl
```

Install
```shell
install -D -m0755 ../../target/x86_64-unknown-linux-gnu/release/ttrpc-cdh-tool /usr/local/bin/ttrpc-cdh-tool
```

#### gRPC Client Tool

run the following to build
```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/confidential-data-hub/hub
cargo build --bin grpc-cdh-tool --features bin,grpc
```

Install
```shell
install -D -m0755 ../../target/x86_64-unknown-linux-gnu/release/grpc-cdh-tool /usr/local/bin/grpc-cdh-tool
```