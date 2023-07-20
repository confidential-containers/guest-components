# Kubernetes Sealed Secret

## Introduction

CoCo’s [threat model](https://github.com/confidential-containers/confidential-containers/blob/main/trust_model_personas.md)
excludes the Kubernetes Control Plane and Host components from the
Trusted Compute Base (TCB). With this stricter threat model, CoCo
runtimes cannot take advantage of the existing infrastructure. to
protect [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/),
this document introduces Sealed Secrets that supports in-pod decryption.

A Sealed Secret is a set of metadata to get the plaintext of the secret.
A Sealed Secret will be unsealed inside the TEE pod transparently to users,
and the unsealing occurs only if the remote attestation process passes,
which means the TEE environment is as expected. Also, Sealed Secret can
leverage commercial KMS/Secret Manager(Vault) productions in the unsealing
process.

## Format

Due to different sealing types, there are two different formats of Sealed
Secrets.

### Envelope

This kind of secret uses envelope encryption scheme. An encryption key is used
to encrypt the plaintext secret value. A sealing key insde a KMS/KBS is used to
seal the encryption key. That is

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
	"annotations": {
		"region_id": "cn-hangzhou",
		"endpoint": "xxx",
		"signature_method": "xxx"
	}
}
```
Here,
- `version`: indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: MUST be `envelope`, indicating this is a Envelope type Sealed Secret
- `provider`: indicates the provider of the __sealing key__. This field determines
how to use the `annotations` field and `key_id` field to decrypt the `encrypted_key`
- `key_id`: To uniquely distinguish the __sealing key__ used to encrypt the __encryption key__,
which is always used by the provider driver.
- `encrypted_key`: Encrypted __encryption key__ by the `provider`. Base64 encoded.
- `encrypted_data`: Encrypted __secret value__ by the `encrypted_key`. Base64 encoded.
- `wrap_type`: The algorithm used by __encryption key__ to encrypt the __secret value__.
`A256GCM` (AES256-GCM) preferred.
- `iv`: The Initial Vector used in the process of __encryption key__ encrypting __secret value__.
Base64 encoded.
- `annotations`: A key-value Map. Provider specific information used by the driver to
decrypt `encrypted_key` into a plaintext of __encryption key__.

### Vault

A Vault secret leverages secret manager mechanism. Vault secret does not require any
encryption. It only contains metadata with which the plaintext of the __secret value__
can be retrieved. The format is
```json
{
	"version" : "0.1.0",
	"type": "vault",
	"provider": "ali",
	"name": "xxx",
	"annotations": {
		"version_id": "xxx",
		"version_stage": "xxx"
	}
}
```
Here,
- `version`: indicates the format version of the Sealed Secret. Currently `0.1.0`.
- `type`: MUST be `vault`, indicating this is a Vault type Sealed Secret.
- `provider`: indicates the provider of the __secret value__. This field determines
how to use the `annotations` field and `name` field to get the plaintext of __secret value__.
- `name`: To uniquely distinguish the __secret value__, which is always used by the provider driver.
- `annotations`: A key-value Map. Vault specific information used by the provider driver to
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

## Usage in CoCo

When we get a Sealed Secret like the following
```json
{
	"version": "0.1.0",
	"type": "kms",
	"provider": "xxx",
	"key_id": "xxx",
	"encrypted_key": "ab27dc=", 
	"encrypted_data": "xxx",
	"wrap_type": "A256GCM",
	"iv": "xxx",
	"annotations": {
		"region_id": "cn-hangzhou",
		"endpoint": "xxx",
		"signature_method": "xxx"
	}
}
```

We can encode the payload in BASE64
```
ewoJInZlcnNpb24iOiAiMC4xLjAiLAoJInR5cGUiOiAia21zIiwKCSJwcm92aWRlciI6ICJ4eHgiLAoJImtleV9pZCI6ICJ4eHgiLAoJImVuY3J5cHRlZF9rZXkiOiAiYWIyN2RjPSIsIAoJImVuY3J5cHRlZF9kYXRhIjogInh4eCIsCgkid3JhcF90eXBlIjogIkEyNTZHQ00iLAoJIml2IjogInh4eCIsCgkiYW5ub3RhdGlvbnMiOiB7CgkJInJlZ2lvbl9pZCI6ICJjbi1oYW5nemhvdSIsCgkJImVuZHBvaW50IjogInh4eCIsCiAgICAgICAgInNpZ25hdHVyZV9tZXRob2QiOiAieHh4IgoJfQp9Cg==
```
Then add a prefix `sealed.`

```
sealed.ewoJInZlcnNpb24iOiAiMC4xLjAiLAoJInR5cGUiOiAia21zIiwKCSJwcm92aWRlciI6ICJ4eHgiLAoJImtleV9pZCI6ICJ4eHgiLAoJImVuY3J5cHRlZF9rZXkiOiAiYWIyN2RjPSIsIAoJImVuY3J5cHRlZF9kYXRhIjogInh4eCIsCgkid3JhcF90eXBlIjogIkEyNTZHQ00iLAoJIml2IjogInh4eCIsCgkiYW5ub3RhdGlvbnMiOiB7CgkJInJlZ2lvbl9pZCI6ICJjbi1oYW5nemhvdSIsCgkJImVuZHBvaW50IjogInh4eCIsCiAgICAgICAgInNpZ25hdHVyZV9tZXRob2QiOiAieHh4IgoJfQp9Cg==
```

Then we can use this in normal Kubernetes Secret. For example a Secret
Declaration
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-secret
type: Opaque
stringData:
  example-key: "sealed.ewoJInZlcnNpb24i..."
```

When this sealed secret is transferred to TEE, Confidential DataHub will help to unseal.

## Sealing & Unsealing of the Secret (TODO)
