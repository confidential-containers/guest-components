Trustee client -- a simple tool to attest and fetch secrets from Trustee

Trustee client is using attestation-agent's kbs_protocol client and
attesters to gather hardware-based confidential-computing evidence
and send it over to Trustee.

Trustee client is a part of [confidential-containers](https://github.com/confidential-containers)
[guest-components](https://github.com/confidential-containers/guest-components)
project but can be used for confidential VMs as well.



Build with:
    cargo build [--no-default-features]


Configuration file:
trustee-client configuration must contain the trustee (server) URL.
Possibly it can also contain the trustee https certificate, either
as a string in the configuration file or in another file (but not both).

A configuration file path is an optional argument to trustee-client
If no configuration file path is provided /etc/trustee-client.conf is used.

Run:
  $ trustee-client [--config-file <path>] get-resource --path <resource-path>

Example:
  $ trustee-client get-resource --path default/keys/dummy
