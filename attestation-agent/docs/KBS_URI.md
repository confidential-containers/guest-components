# KBS Resource URI

## Introduction

To uniquely identify every resource/key in the CoCo Key Broker System, a __KBS Resource URI__ is defined.

## Specification

A KBS Resource URI must comply with the following format:

```plaintext
kbs://<kbs_host>:<kbs_port>/<repository>/<type>/<tag>
```

where:

- `kbs://`: This is the fixed, custom KBS resource scheme. It indicates that this URI for a [CoCo KBS](https://github.com/confidential-containers/kbs/tree/main/kbs) resource.
- `<kbs_host>:<kbs_port>`: This the KBS host address and port. It is either an IP address or a domain name, and an *optional* TCP/UDP port. Also can be treated as a `confidential resource registry`.
- `<repository>/<type>/<tag>`: This is the resource path. Typically, `<repository>` would be a user name, `<type>` would be the type of the resource, and `<tag>` would help distinguish between different resource instances of the same type.

For example: `kbs://example.cckbs.org:8081/alice/decryption-key/1`

## How Different KBC/KBS uses a KBS Resource URI

### CC-KBC

`CC-KBC` will convert a KBS Resource URI into a [CoCo KBS Resource API](https://github.com/confidential-containers/kbs/blob/main/kbs/docs/kbs.yaml#L100) compliant HTTP/HTTPS request.
For example, a KBS Resource URI `kbs://example.cckbs.org/alice/decryption-key/1` will be converted to `http://example.cckbs.org/kbs/v0/resource/alice/decryption-key/1`.

### EAA KBC & Online SEV KBC

Both KBCs will use the `<repository>/<type>/<tag>` as key/resource id in their requests.

### Offline KBCs (e.g FS KBC)

Offline KBCs should ignore the `<kbs_host>:<kbs_port>` host part of the URI, and use the resource path (`<repository>/<type>/<tag>`) to locally fetch the resource.
