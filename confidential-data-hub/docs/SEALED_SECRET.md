# Sealed Secrets

## Introduction

In Confidential Containers, secrets can be protected with sealing.
A sealed secret is a way to encapsulate confidential data
such that it can be accessed only inside an enclave
in conjunction with an attestation.

The Confidential Data Hub provides an API for unsealing secrets inside
of a confidential guest.

You can also use the secret cli tool to generate a sealed secret:

```bash
cargo run -p confidential-data-hub --bin secret
```

## Kubernetes Secrets

CoCo’s [threat model](https://github.com/confidential-containers/confidential-containers/blob/main/trust_model_personas.md)
excludes the Kubernetes Control Plane and Host components from the
Trusted Compute Base (TCB).
This means that CoCo workloads should not store sensitive data
with traditional [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/).

Instead, Kubernetes secrets can be created from sealed secrets,
allowing the control plane to orchestrate the secrets without
being able to read them. This is shown in detail below.

The Kata Agent, in conjunction with the CDH, can transparently
provision these secrets as environment variables.

## Comparison to Resource URI

Confidential Containers also uses Resource URIs to refer to secrets.
Unlike resource URIs, sealed secrets contain configuration metadata
that partially decouples unsealing the secret from the general attestation
configuration.

For example, a sealed secret can be unwrapped by an HSM while all other
secret resources are fetched from the KBS.
Sealed secrets can be used to create complex environments where multiple
secrets, fulfilled by different parties, can all travel along with the workload.

## Format

There are two main types of sealed secrets.

### Envelope

This kind of secret uses envelope encryption scheme. An encryption key is used
to encrypt the plaintext secret value. The wrapped secret is stored as part of
the sealed secret.
To unseal the secret, a KMS/KBS is used to unwrap the encryptd key.

$$Sealed Secret := \{Enc_{Sealing key}(Encryption Key), Enc_{Encryption Key}(secret value)\}$$

The format of the KMS type Sealed Secret is
```json
{
	"version": "0.1.0",
	"type": "envelope",
	"provider": "xxx",
	"key_id": "xxx",
	"encrypted_key": "ab27dc=",
	"encrypted_data": "xxx",
	"wrap_type": "A256GCM",
	"iv": "xxx",
	"provider_settings": {
		...
	},
	"annotations": {
		...
	}
}
```
Here,
- `version`: **REQUIRED**. indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: **REQUIRED**. MUST be `envelope`, indicating this is a Envelope type Sealed Secret
- `provider`: **REQUIRED**. indicates the provider of the __sealing key__. This field determines
how to use the `annotations` field and `key_id` field to decrypt the `encrypted_key`
- `key_id`: **REQUIRED**. To uniquely distinguish the __sealing key__ used to encrypt the __encryption key__,
which is always used by the provider driver.
- `encrypted_key`: **REQUIRED**. Encrypted __encryption key__ by the `provider`. Base64 encoded.
- `encrypted_data`: **REQUIRED**. Encrypted __secret value__ by the `encrypted_key`. Base64 encoded.
- `wrap_type`: **REQUIRED**. The algorithm used by __encryption key__ to encrypt the __secret value__.
`A256GCM` (AES256-GCM) preferred.
- `iv`: **REQUIRED**. The Initial Vector used in the process of __encryption key__ encrypting __secret value__.
Base64 encoded.
- `provider_settings`: **REQUIRED**. A key-value map. Provider specific information to create the KMS client.
- `annotations`: **OPTIONAL**. A key-value Map. Provider specific information used by the driver to
decrypt `encrypted_key` into a plaintext of __encryption key__.

### Vault

A vault secret is simply a pointer to a secret that is stored elsewhere,
either in a KMS or KBS.
To fulfill a vault secret, the CDH will retrieve the secret itself from
a secret provider.

Creating a vault secret does not require any encryption.
Simply create the metadata below and provision your secret
to the provider.
```json
{
	"version" : "0.1.0",
	"type": "vault",
	"provider": "xxx",
	"name": "xxx",
	"provider_settings": {
		...
	},
	"annotations": {
		...
	}
}
```
Here,
- `version`: **REQUIRED**. indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: **REQUIRED**. MUST be `vault`, indicating this is a Vault type Sealed Secret.
- `provider`: **REQUIRED**. indicates the provider of the __secret value__. This field determines
how to use the `annotations` field and `name` field to get the plaintext of __secret value__.
- `name`: **REQUIRED**. To uniquely distinguish the __secret value__, which is always used by the provider driver.
- `provider_settings`: **REQUIRED**. A key-value map. Provider specific information to create the vault client.
- `annotations`: **OPTIONAL**. A key-value Map. Vault specific information used by the provider driver to
get the plaintext of the __secret value__.

## Integrity Protection of Sealed Secret

Widely used [JWS](https://datatracker.ietf.org/doc/html/rfc7515) is used to protect
the integrity of a Sealed Secret.
A Sealed Secret is the payload of a JWS. A signed Sealed Secret is as following
```
BASE64URL(UTF8(JWS Protected Header)) || '.
    || BASE64URL(JWS Payload) || '.'
    || BASE64URL(JWS Signature)
```

We can leverage the ["kid"](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4)
field to specify the public key used to verify this signature.

Signatures for secrets are not yet implemented, but sealed secrets are
required to have a header and signature. A sealed secret should be of the form

`sealed`.`JWS header`.`JWS body (secret content)`.`signature`

Since signature verification is not yet supported, dummy values
can be used for the header and signature. A sealed secret could look like this.

```
secret=sealed.fakejwsheader.ewogICAgInZlcnNpb24iOiAiMC4xLjAiLAogICAgInR5cGUiOiAidmF1bHQiLAogICAgIm5hbWUiOiAia2JzOi8vL2RlZmF1bHQvc2VhbGVkLXNlY3JldC90ZXN0IiwKICAgICJwcm92aWRlciI6ICJrYnMiLAogICAgInByb3ZpZGVyX3NldHRpbmdzIjoge30sCiAgICAiYW5ub3RhdGlvbnMiOiB7fQp9Cg.fakesignature
```

## Usage in CoCo

You can create a Kubernetes secret from a sealed secret
and Kata will automatically expose it to your workload.

Start with a sealed secret such as
```json
{
	"version": "0.1.0",
	"type": "envelope",
	"provider": "xxx",
	"key_id": "xxx",
	"encrypted_key": "ab27dc=",
	"encrypted_data": "xxx",
	"wrap_type": "A256GCM",
	"iv": "xxx",
	"provider_settings": {
		...
	},
	"annotations": {
		...
	}
}
```

Encode the payload in BASE64URL
```
ewoJInZlcnNpb24iOiAiMC4xLjAiLAoJInR5cGUiOiAiZW52ZWxvcGUiLAoJInByb3ZpZGVyIjogInh4eCIsCgkia2V5X2lkIjogInh4eCIsCgkiZW5jcnlwdGVkX2tleSI6ICJhYjI3ZGM9IiwgCgkiZW5jcnlwdGVkX2RhdGEiOiAieHh4IiwKCSJ3cmFwX3R5cGUiOiAiQTI1NkdDTSIsCgkiaXYiOiAieHh4IiwKCSJhbm5vdGF0aW9ucyI6IHsKCQkiY3J5cHRvX2NvbnRleHQiOiB7CgkJCSJhbGdvcml0aG0iOiAiQTI1NkdDTSIKCQl9LAoJCSJwcm92aWRlcl9zZXR0aW5nIjogewoJCQkia21zX2luc3RhbmNlX2lkIjogInh4eCIKCQl9Cgl9Cn0
```
Then add a prefix `sealed.` and JWS header and signature.

```
sealed.fakejwsheader.ewoJInZlcnNpb24iOiAiMC4xLjAiLAoJInR5cGUiOiAiZW52ZWxvcGUiLAoJInByb3ZpZGVyIjogInh4eCIsCgkia2V5X2lkIjogInh4eCIsCgkiZW5jcnlwdGVkX2tleSI6ICJhYjI3ZGM9IiwgCgkiZW5jcnlwdGVkX2RhdGEiOiAieHh4IiwKCSJ3cmFwX3R5cGUiOiAiQTI1NkdDTSIsCgkiaXYiOiAieHh4IiwKCSJhbm5vdGF0aW9ucyI6IHsKCQkiY3J5cHRvX2NvbnRleHQiOiB7CgkJCSJhbGdvcml0aG0iOiAiQTI1NkdDTSIKCQl9LAoJCSJwcm92aWRlcl9zZXR0aW5nIjogewoJCQkia21zX2luc3RhbmNlX2lkIjogInh4eCIKCQl9Cgl9Cn0.fakesignature
```

Create a Kubernetes secret

```bash
kubectl create secret generic sealed-secret --from-literal='secret=sealed.fakejwsheader.ewoJInZlcnNpb24i...'
```

Use this secret in a workload
```yaml
...
    env:
    - name: PROTECTED_SECRET
      valueFrom:
        secretKeyRef:
          name: sealed-secret
          key: secret
```

Your secret will be provisioned to the `PROTECTED_SECRET` environment variable.

## Supported Providers

| Provider Name      | README                                                      			| Maintainer                |
| ------------------ | -------------------------------------------------------------------- | ------------------------- |
| aliyun       	     |  [aliyun](kms-providers/alibaba.md)                               	| Alibaba                   |
| ehsm       	     |  [ehsm](kms-providers/ehsm-kms.md)                              		| Intel                   	|
| kbs                |                                                                          | CoCo                  |

