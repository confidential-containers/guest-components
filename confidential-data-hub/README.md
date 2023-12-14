# Confidential Data Hub

Confidential Data Hub is a service running inside guest to provide resource related
APIs.



### Build

Build and install with default KBC modules:

```shell
git clone https://github.com/confidential-containers/guest-components
cd guest-components/confidential-data-hub
make
```

or explicitly specify the confidential resource provider and KMS plugin, please refer to
[Supported Features](#supported-features)

```shell
make RESOURCE_PROVIDER=kbs PROVIDER=aliyun
```

### Supported Features

Confidential resource providers (flag `RESOURCE_PROVIDER`)

| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| kbs                 | For TDX/SNP/Azure-SNP-vTPM based on KBS Attestation Protocol       |
| sev                 | For SEV based on efi secret pre-attestation                        |

Note: `offline-fs` is built-in, we do not need to manually enable. If no `RESOURCE_PROVIDER`
is given, all features will be enabled.

KMS plugins (flag `PROVIDER`)

| Feature name        |           Note                                                     |
| ------------------- | -----------------------------------------------------------------  |
| aliyun              | Use aliyun KMS suites to unseal secrets, etc.                      |
| ehsm                | Use Intel eHSM KMS suites to unseal secrets, etc.                  |

Note:  If no `PROVIDER` is given, all features will be enabled.
