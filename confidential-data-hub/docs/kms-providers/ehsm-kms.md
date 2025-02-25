# KMS Driver for eHSM-KMS

## Spec

### Consts & Layouts

Here are the consts for eHSM-KMS.

| Name               | Value       |
| ------------------ | ----------- |
| `provider`       	 | `ehsm`       |

The `provider_settings` and `annotations` defined in [Sealed Secret](../SEALED_SECRET.md#format) is as following:

#### annotations

##### encryption/decryption

The `annotations` should be set empty.

#### provider_settings

| Name               | Usage                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `app_id`           | App ID of the eHSM-KMS instance that user created.                   |
| `endpoint`         | Address of the eHSM-KMS instance.                                     |

### Credential files

To connect to a KMS instance, a credential file is needed. A credential file is actually
[an json file with app_id and api_key](../../kms/src/plugins/ehsm/example_credential/credential.4eb1____.json). 
The name of the credential file is always derived from the app id. Suppose the
App ID is `xxx`, then the credential file has name `credential.xxx.json`.

For more details please see the [`Enroll` operation of ehsm](https://github.com/intel/ehsm/blob/main/docs/API_Reference.md#Enroll).

## Behavior

The client `EhsmKmsClient` supports `Encrypter` and `Decrypter` api. When at the
user side, the credential files can be directly given by the user.

When in Tee, the credential files is supposed to be placed under `/run/confidential-containers/cdh/kms-credential/ehsm` directory.

## Sealed Secrets

This section introduces how to use `ehsm` KMS to seal a secret.

Suppose that we login on a machine where we can connect to a eHSM-KMS instance.

Prepare the following files
- `kms-key-id.txt`: The content is the key id of the symmetric key. Example
```
a3c2...
```
- `kms-endpoint.txt`: The content is the key id of the symmetric key. Example
```
https://1.2.3.4:9000
```
- `Credential.json`: The content is the AppID and ApiKey. Example
```json
{
  "AppId": "2eb6****",
  "ApiKey": "TvMB****"
}
```
- `plaintext`: The file whose content will be sealed.

Then, let's 
```bash
# define the parameters
KEY_ID=$(cat kms-key-id.txt)
ENDPOINT=$(cat kms-endpoint.txt)
CREDENTIAL_FILE_PATH=$(pwd)/Credential.json

git clone https://github.com/confidential-containers/guest-components.git && cd guest-components

cargo build --bin secret_cli --release --features ehsm

target/release/secret_cli seal --file-path ../plaintext \
    envelope --key-id $KEY_ID ehsm \
    --credential-file-path $CREDENTIAL_FILE_PATH \
    --endpoint $ENDPOINT \
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
    "key_id": "a3c2...",
    "encrypted_key": "STBp...",
    "encrypted_data": "QzWk...",
    "wrap_type": "A256GCM",
    "iv": "T32...",
    "provider": "ehsm",
    "provider_settings": {
        "app_id": "2eb6...",
        "endpoint": "https://1.2.3.4:9000"
    },
    "annotations": {}
}
```
