# KBS Resource URI

## Introduction

To uniquely identify every resource/key in the CoCo Key Broker System, a __KBS Resource URI__ is defined.

## Specification

The format of a KBS Resource URI is

```plaintext
kbs://<url-of-kbs>/<repository>/<type>/<tag>
```

Here,
- `kbs://`: a fixed scheme, indicating that this uri is a KBS Resource URI and used in CoCo Key Broker System.
- `<url-of-kbs>`: the address of the KBS which stores the resource. It is either a ip address or a domain name. Also can be treated as a `confidential resource registry`. Currently, we do not actually use this field in the code, so a uri looks like `kbs:///...`.
- `<repository>/<type>/<tag>`: They compose a path to the resource altogether. Usually, `<repository>` can be a user name, `<type>` can be the type of the resource, and `<tag>` to distinguish different instances of the same type. The default value of `<repository>` is `default`.

## How Different KBC/KBS uses a KBS Resource URI

### CC-KBC

CC-KBC will convert a KBS Resource URI into a web link to request a [coco-KBS](https://github.com/confidential-containers/kbs). The web link follows the [OpenAPI of KBS](https://github.com/confidential-containers/kbs/blob/main/docs/kbs.yaml#L74).
For example, a KBS Resource URI `kbs://example.cckbs.org/alice/decryption-key/1` will be converted to `http://example.cckbs.org/kbs/v0/resource/alice/decryption-key/1`.

### EAA KBC & Online Sev KBC

Both KBCs will use the `<repository>/<type>/<tag>` as key/resource id in their requests.

### Offline Fs KBC & Offline Sev KBC

Both KBCs are local KBC. They will ignore the `<url-of-kbs>` field, and use the `<repository>/<type>/<tag>` as key/resource id to index the resource.
