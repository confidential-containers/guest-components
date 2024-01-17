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
| ehsm                | Use Intel eHSM KMS_PROVIDER suites to unseal secrets, etc.                  |

Note:
- If no `KMS_PROVIDER` flag is given, then all the KMS providers will be enabled by default.
