# Confidential Data Hub

Confidential Data Hub (`CDH`) is a service running inside the guest to provide resource related
APIs.

### APIs

The APIs are defined in the [proto file](../protos/protos/confidential-data-hub).

Note that CDH supports decryption of encrypted images.
When `OCICRYPT_KEYPROVIDER_CONFIG` is unset, CDH writes a default ocicrypt
keyprovider config that maps the `attestation-agent` provider to CDH's own
socket (from the CDH config). Operators can still override by pointing
`OCICRYPT_KEYPROVIDER_CONFIG` at a custom file, for example:

```shell
OCICRYPT_KEYPROVIDER_CONFIG=<path-to-ocicrypt_config.json> confidential-data-hub
```

An example config file is at [hub/src/image/ocicrypt_config.json](./hub/src/image/ocicrypt_config.json).

### Build

Build and install with default features:

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/confidential-data-hub
make
```
This will build CDH with `kbs` enabled.

Cloud KMS plugins are off by default. Enable them explicitly with
`KMS_PROVIDER`, for example Aliyun KMS:

```shell
make KMS_PROVIDER=aliyun
```

Or AWS KMS / Secrets Manager:

```shell
make KMS_PROVIDER=aws
```

If you only want the builtin `offline_fs_kbc` (no `cc_kbc`):
```shell
make ENABLE_KBS=false
```

The default CDH runs as a service daemon. If you want to build CDH to an one-shot binary (run once and exit), use flag `ONE_SHOT=true`
```shell
make ONE_SHOT=true
```

Please refer to [Supported Features](#supported-features) for the options.

### Supported Features

CoCo KBS / `cc_kbc` (flag `ENABLE_KBS`)

| Value  | Note                                                                 |
| ------ | -------------------------------------------------------------------- |
| true   | Enable cargo feature `kbs` (`cc_kbc` with KBS attestation protocol). Default. |
| false  | Build without `cc_kbc`. `offline_fs_kbc` is still available.         |

Note:
- Omit `ENABLE_KBS` to keep the default (`true`). Only set it when disabling.

KMS_PROVIDER plugins (flag `KMS_PROVIDER`)

| Feature name | Note                                                        |
| ------------ | ----------------------------------------------------------- |
| aliyun       | Use Alibaba Cloud KMS to seal and unseal secrets.           |
| aws          | Use AWS KMS and Secrets Manager for confidential secrets.   |

Note:
- Omit `KMS_PROVIDER` (or set `none`) to build without cloud KMS plugins.
  Pass `aliyun` and/or `aws` only when those providers are needed.

RPC plugins (flag `RPC`)
| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| grpc                | Use grpc API to serve for requests (TCP/IP socket).                |
| ttrpc               | Use ttrpc API to serve for requests (Unix socket).                 |

Secure mount plugins (flag `STORAGE`)

Note:
- If no `STORAGE` flag is given, then all the STORAGE plugins will be enabled by default.

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
