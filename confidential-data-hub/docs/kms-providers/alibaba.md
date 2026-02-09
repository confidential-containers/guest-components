# KMS Driver for Aliyun

## Spec

### Consts & Layouts

Here are the consts for Aliyun KMS.

| Name               | Value       |
| ------------------ | ----------- |
| `provider`       	 | `aliyun`       |

The `provider_settings` and `annotations` defined in [Sealed Secret](../SEALED_SECRET.md#format) is as following:

#### annotations

##### encryption/decryption

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `iv`       	     | The initialization vector used in an encryption/decryption operation |

##### get_secret

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `version_stage`    | (Optional) If this parameter is specified, KMS returns the credentials value of the version that is marked as the specified status. |
| `version_id`       | (Optional) If this parameter is specified, KMS returns the credentials value for the specified version number. |

#### provider_settings

`client_type` is used to specify the method of accessing KMS. Only 'client_key' is avaliable for encryption/decryption. While both 'client_key' and 'ecs_ram_role' are avaliable for get_secret.

If `client_type` is set to 'client_key', provider_settings shall be as following:

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `client_type`      | Used to specify the method of accessing KMS. ('client_key' is set here) |
| `client_key_id`    | The ID of the client key used to access the KMS instance             |
| `kms_instance_id`  | The KMS instance ID to be connected                                  |

Else if `client_type` is set to 'ecs_ram_role', provider_settings shall be as following:

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `client_type`      | Used to specify the method of accessing KMS. ('ecs_ram_role' is set here) |

Else if `client_type` is set to 'sts_token', provider_settings shall be as following:

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `client_type`      | Used to specify the method of accessing KMS. ('sts_token' is set here) |
| `token_path`       | STS Token path inside the pod. The format of STS token is `AK:SK:STS`|
| `region_id`        | KMS instance region ID                                               |

### Credential files

To connect to a KMS instance with `client_type` set to 'client_key', a client key is needed. A client key is actually
[an json with encrypted inside](../../kms/src/plugins/aliyun/client/client_key_client/example_credential/clientKey_KAAP.f4c8____.json)
private key. The name of the client key is always derived from the client key id. Suppose the
client key ID is `xxx`, then the client key file has name `clientKey_xxx.json`. The key to encrypt
the private key is derived from a password that is also saved in [a file](../../kms/src/plugins/aliyun/client/client_key_client/example_credential/password_KAAP.f4c8____.json).
Suppose the client key ID is `xxx`, then the password file has name `password_xxx.json`.
Besides, [a cert of the KMS server](../../kms/src/plugins/aliyun/client/client_key_client/example_credential/PrivateKmsCA_kst-shh64702cf2jvc_____.pem)
is also needed. Suppose the kms instance id is `xxx`, then the cert of the KMS server has name `PrivateKmsCA_xxx.pem`.

For more details please see the [developer document for aliyun](https://www.alibabacloud.com/help/en/key-management-service/latest/api-overview).

To connect to a KMS instance with `client_type` set to 'ecs_ram_role', a [ecsRamRole.json](../../kms/src/plugins/aliyun/client/ecs_ram_role_client/example_credential/ecsRamRole.json) file is needed.
In the json file, `ecs_ram_role_name` and `region_id` is set in order to get access to Dedicated KMS.
Among them，`ecs_ram_role_name` refer to RAM role for ECS instances in a VPC network, where CDH runs. Can be set on Aliyun Console.
And `region_id` refers to region id of Dedicated KMS, to which more details can be refered [here](https://www.alibabacloud.com/help/en/kms/product-overview/supported-regions).

More details about accessing via EcsRamRole can be seen at [Access KMS from an ECS instance in a secure manner](https://www.alibabacloud.com/help/en/kms/use-cases/access-kms-from-an-ecs-instance-in-a-secure-manner).

## Behavior

The client `AliyunKmsClient` supports `Encrypter`, `Decrypter`, and `Getter` api. When at the
user side, the credential files can be directly given by the user.

When in Tee, the credential files is supposed to be placed under `/run/confidential-containers/cdh/kbs/kms-credential/aliyun` directory.

## Sealed Secrets

This section introduces how to use `aliyun` KMS to seal a secret.

Suppose that we login on an ECS machine where we can connect to a KMS instance.

Prepare the following files
- `kms-key-id.txt`: The content is the key id of the symmetric key. Example
```
key-bjj...
```
- `kms-instance-id.txt`: The content is the instance id of the kms. Example
```
kst-bjj652...
```
- `ClientKeyPassword.json`: The content is the password of the password of the ClientKey. Example
```json
1e367c6b24...
```
- `ClientKeyContent.json`: The content is the ClientKeyContent. Example
```json
{
  "KeyId": "KAAP.e9692...",
  "PrivateKeyData": "MIIJ2wIBAzCC..."
}
```
- `ca.pem`: The public key certificate of the KMS instance. Example
```
-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIJALTKwWAjvbMiMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV
...
nc8BTncWI0KGWIzTQasuSEye50R6gc9wZCGIElmhWcu3NYk=
-----END CERTIFICATE-----
```
- `plaintext`: The file whose content will be sealed.

Then, let's 
```bash
# define the parameters
KEY_ID=$(cat kms-key-id.txt)
KMS_INSTANCE_ID=$(cat kms-instance-id.txt)
CLIENT_KEY_PASSWORD_FILE_PATH=$(pwd)/ClientKeyPassword.json
CERT_PATH=$(pwd)/ca.pem
CLIENT_KEY_FILE_PATH=$(pwd)/ClientKeyContent.json

git clone https://github.com/confidential-containers/guest-components.git && cd guest-components

cargo build --bin secret_cli --release --features "aliyun"

target/release/secret_cli seal --file-path ../plaintext \
    envelope --key-id $KEY_ID ali \
    --password-file-path $CLIENT_KEY_PASSWORD_FILE_PATH \
    --cert-path $CERT_PATH \
    --kms-instance-id $KMS_INSTANCE_ID \
    --client-key-file-path $CLIENT_KEY_FILE_PATH \
    > sealed_secret.json
```

Finally the sealed secret will be output to `sealed_secret.json`.

```bash
cat sealed_secret.json | python -m json.tool
```

And the output
```json
{
    "version": "0.1.0",
    "type": "envelope",
    "key_id": "key-bj...",
    "encrypted_key": "XTXa...",
    "encrypted_data": "7vfE...",
    "wrap_type": "A256GCM",
    "iv": "Q/g...",
    "provider": "aliyun",
    "provider_settings": {
        "client_type": "client_key",
        "client_key_id": "KAAP.e9...",
        "kms_instance_id": "kst-bj..."
    },
    "annotations": {
        "iv": "s2O..."
    }
}
```
