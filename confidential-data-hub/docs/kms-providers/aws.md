# KMS Driver for AWS

This driver backs two kinds of sealed secrets:

- **Envelope secrets** via [AWS KMS](https://aws.amazon.com/kms/). The
  data-encryption-key (DEK) is wrapped/unwrapped with the KMS `Encrypt`/`Decrypt`
  operations.
- **Vault secrets** via [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).
  The pointed-to value is fetched with `GetSecretValue`.

Both are served by a single client (`AwsKmsClient`) authenticated with one set of
static IAM credentials.

## Spec

### Consts & Layouts

| Name         | Value   |
| ------------ | ------- |
| `provider`   | `aws`   |

The `provider_settings` and `annotations` defined in [Sealed Secret](../SEALED_SECRET.md#format)
are as follows:

#### provider_settings

| Name       | Usage                                                     |
| ---------- | --------------------------------------------------------- |
| `region`   | AWS region of the KMS key / secret, e.g. `us-east-1`.     |

The KMS key identifier (key id, ARN, or `alias/...`) is carried in the sealed
secret's `key_id` field for envelope secrets. The Secrets Manager secret id
(name or ARN) is carried in the `name` field for vault secrets.

#### annotations

##### encryption/decryption (envelope)

| Name                 | Usage                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------- |
| `encryption_context` | (Optional) AWS KMS encryption context (AAD). If set at seal time it must match at unseal time.     |

By default this is empty. When an `encryption_context` is provided it is passed
to KMS `Encrypt` at seal time and bound into the ciphertext; the identical
context must then be supplied to `Decrypt` at unseal time or the operation
fails. AWS KMS embeds the IV/nonce in the ciphertext blob, so no `iv` annotation
is used.

##### get_secret (vault)

| Name             | Usage                                                                       |
| ---------------- | --------------------------------------------------------------------------- |
| `version_id`     | (Optional) Fetch a specific version of the secret. Empty = current version. |
| `version_stage`  | (Optional) Staging label to fetch. Empty = `AWSCURRENT`.                     |

### Credential files

To connect to AWS a credential file is needed. It is a JSON document with static
IAM credentials:

```json
{
  "access_key_id": "AKIA...",
  "secret_access_key": "...",
  "session_token": null
}
```

`session_token` is optional and only used for temporary (STS) credentials.

When in a TEE, the credential file is supposed to be placed at
`/run/confidential-containers/cdh/kbs/kms-credential/aws/credential.json`.
The location can be overridden with the `AWS_IN_GUEST_KEY_PATH` environment
variable (the file name inside that directory is always `credential.json`).

The recommended way to provision the file is the CDH credential interface: add a
`[[credentials]]` entry to the CDH config so the file is fetched from the KBS,
attestation-gated, when CDH starts. Store the JSON credential document shown
above as a KBS resource, then reference it:

```toml
[[credentials]]
path = "/run/confidential-containers/cdh/kbs/kms-credential/aws/credential.json"
resource_uri = "kbs:///default/aws/credential"
```

`path` must be under `/run/confidential-containers/cdh/kbs`, and it must match
the directory the driver reads (the default above, or whatever
`AWS_IN_GUEST_KEY_PATH` points at).

> [!IMPORTANT]
> Static IAM keys do not rotate on their own; prefer scoping them tightly (a
> dedicated IAM principal allowed only `kms:Decrypt` on the specific key and/or
> `secretsmanager:GetSecretValue` on the specific secret) and rotating them out
> of band.

## Behavior

`AwsKmsClient` implements `Encrypter`, `Decrypter`, `Getter`, and `Setter`.
`Encrypter`/`Setter` are used on the user side (sealing/provisioning), while
`Decrypter`/`Getter` are used in-guest (unsealing).

The client is constructed directly from the region and static credentials; it
does **not** perform ambient AWS credential discovery (no environment/instance
metadata scanning), which keeps the in-guest attack surface minimal.

## Sealed Secrets

### Envelope

Suppose we are on a machine that can reach AWS with an IAM principal allowed to
`kms:Encrypt` on the target key.

Prepare:
- `kms-key-id.txt`: the KMS key id/ARN/alias, e.g. `alias/my-coco-key`
- `aws-region.txt`: e.g. `us-east-1`
- `aws-credential.json`: the credential file shown above
- `plaintext`: the file whose content will be sealed

A prebuilt `secret` CLI (with all KMS providers bundled) is available from the
[GitHub releases](https://github.com/confidential-containers/guest-components/releases);
using it lets you skip the build-from-source step below.

```bash
KEY_ID=$(cat kms-key-id.txt)
REGION=$(cat aws-region.txt)
CREDENTIAL_FILE_PATH=$(pwd)/aws-credential.json

git clone https://github.com/confidential-containers/guest-components.git && cd guest-components

cargo build -p confidential-data-hub --bin secret --features aws

target/debug/secret seal \
    --signing-kid kbs://signing/key/uri --signing-jwk-path ./path/to/jwk \
    envelope --key-id "$KEY_ID" --file-path ../plaintext \
    aws \
    --region "$REGION" \
    --credential-file-path "$CREDENTIAL_FILE_PATH" \
    > sealed_secret.json
```

The resulting `sealed_secret.json` looks like:

```json
{
    "version": "0.1.0",
    "type": "envelope",
    "key_id": "alias/my-coco-key",
    "encrypted_key": "AQIDAH...",
    "encrypted_data": "QzWk...",
    "wrap_type": "A256GCM",
    "iv": "T32...",
    "provider": "aws",
    "provider_settings": {
        "region": "us-east-1"
    },
    "annotations": {}
}
```

### Vault

A vault secret is just a pointer; the value must be provisioned to AWS Secrets
Manager separately (e.g. `aws secretsmanager create-secret ...`).

```bash
cargo run -p confidential-data-hub --bin secret --features aws -- seal \
    --signing-kid kbs://signing/key/uri --signing-jwk-path ./path/to/jwk \
    vault \
    --resource-uri my/secret/name \
    --provider aws \
    --provider-settings '{"region":"us-east-1"}'
```

## Unsealing

Unsealing happens in-guest via the CDH, but can be exercised with the CLI by
pointing `--key-path` at the directory that directly contains `credential.json`
(this sets `AWS_IN_GUEST_KEY_PATH`, and the driver reads
`$AWS_IN_GUEST_KEY_PATH/credential.json`):

```bash
target/debug/secret unseal \
    --file-path sealed_secret.json \
    --key-path /path/to/dir/containing/credential.json
```
