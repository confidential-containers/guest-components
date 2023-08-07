# KMS Driver for Aliyun

## Spec

### Consts & Layouts

Here are the consts for Aliyun KMS.

| Name               | Value       |
| ------------------ | ----------- |
| `provider`       	 | `aliyun`       |

The `provider_settings` and `annotations` defined in [Sealed Secret](../SEALED_SECRET.md#format) is as following:

#### annotations

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `iv`       	     | The initialization vector used in an encryption/decryption operation |

#### provider_settings

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `client_key_id`    | The ID of the client key used to access the KMS instance             |
| `kms_instance_id`  | The KMS instance ID to be connected                                  |

### Credential files

To connect to a KMS instance, a client key is needed. A client key is actually
[an json with encrypted inside](../../kms/src/plugins/aliyun/example_credential/clientKey_KAAP.f4c8____.json)
private key. The name of the client key is always derived from the client key id. Suppose the
client key ID is `xxx`, then the client key file has name `clientKey_xxx.json`. The key to encrypt
the private key is derived from a password that is also saved in [a file](../../kms/src/plugins/aliyun/example_credential/password_KAAP.f4c8____.json).
Suppose the client key ID is `xxx`, then the password file has name `password_xxx.json`.

To connect to a KMS server, [a cert of the KMS server](../../kms/src/plugins/aliyun/example_credential/PrivateKmsCA_kst-shh64702cf2jvc_____.pem)
is also needed. Suppose the kms instance id is `xxx`, then the cert of the KMS server has name `PrivateKmsCA_xxx.pem`.

For more details please see the [developer document for aliyun](https://www.alibabacloud.com/help/en/key-management-service/latest/api-overview?spm=a2c63.l28256.0.0.bc4f4c6fB82yGa).

## Behavior

The client `AliyunKmsClient` supports both `Encrypter` and `Decrypter` api. When at the
user side, the credential files can be directly given by the user.

When in Tee, the credential files is supposed to be placed under `/run/confidential-containers/cdh/kms-credential/aliyun` directory.
