# Trustee attester #

A tool to attest and fetch secrets from Trustee

Trustee attester is a part of [confidential-containers](https://github.com/confidential-containers)
[guest-components](https://github.com/confidential-containers/guest-components)
project but can be used for confidential VMs as well.

Trustee attester is using attestation-agent's kbs_protocol client and
attesters to gather hardware-based confidential-computing evidence
and send it over to Trustee.

A resource with exact same path must be uploaded to Trustee before trustee-attester runs.


## Build: ##

```bash
cargo build -p kbs_protocol --bin trustee-attester --no-default-features
--features "background_check,passport,bin,<attesters-list>"
```

## Run: ##

```bash
$ trustee-attester --url <Trustee-URL> [--cert-file <path>] get-resource --path <resource-path> [--initdata <initdata> | --attestation-result <base64-json>]
$ trustee-attester --url <Trustee-URL> [--cert-file <path>] attest [--initdata <initdata>]
```

The `attest` command performs attestation without requesting a resource. It prints one
Base64-encoded JSON object containing the generated private TEE key in PEM format and the
attestation token:

```json
{
  "key": "-----BEGIN PRIVATE KEY-----\n...",
  "token": "<JWT>"
}
```

The output can be decoded with:

```bash
$ trustee-attester --url http://localhost:50000 attest | base64 --decode | jq .
```

The decoded output contains private key material and must be handled as a secret.

The result can be reused to fetch resources without performing another attestation:

```bash
$ ATTESTATION_RESULT=$(trustee-attester --url http://localhost:50000 attest)
$ trustee-attester --url http://localhost:50000 get-resource \
    --path default/keys/dummy \
    --attestation-result "$ATTESTATION_RESULT"
```

When `--attestation-result` is supplied, `get-resource` uses its key and token directly.
It cannot be combined with `--initdata`, because no new attestation is performed.

## Example: ##

```bash
$ trustee-attester --url http://localhost:50000 get-resource --path default/keys/dummy
```
