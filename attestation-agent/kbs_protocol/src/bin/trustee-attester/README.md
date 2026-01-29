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
--features "background_check,passport,<openssl|rust-crypto>,bin,<attesters-list>"
```

## Run: ##

```bash
$ trustee-attester --url <Trustee-URL> [--cert-file <path>] get-resource --path <resource-path> [--initdata <initdata> --plugin <plugin>]
```

## Example: ##

```bash
$ trustee-attester --url http://localhost:50000 get-resource --path default/keys/dummy
```
