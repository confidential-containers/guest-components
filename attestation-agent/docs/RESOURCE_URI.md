# Resource URIs

## Introduction

Resource URIs are used across Confidential Containers to identify resources.
For example, the metadata of an encrypted image can contain a resource URI
referencing the image decryption key.
An image signature policy or a sealed secret can contain a resource URI.

Although these have been referred to as KBS Resource URIs, this abstraction
is implemented by the CDH.

The resource URI is not the same thing as the path for requesting a resource
from Trustee's REST API. The mapping between these is described below.

Technically, the Resource URI is not tied to any specific KBS, but this document
mainly focuses on Trustee and the CC_KBC and describes how the resource URI
relates to Trustee.
Some legacy code, such as the SEV KBC or the FS KBC may fulfill resource URIs
in different ways.

## Specification

A Resource URI must comply with the following format:

```plaintext
kbs[+<plugin>]://<kbs_host>:<kbs_port>/<path>[/<path>...][?<query>]
```

The path after the authority consists of one or more slash-separated segments.
There is no fixed limit on how many segments a URI may contain.

### Plugin

The optional `<plugin>` field in the scheme identifies which Trustee plugin fulfills the resource.
If not given, by default `resource` plugin is used.

- `kbs://` — shorthand for the default `resource` plugin.
- `kbs+<plugin>://` — request the resource from a specific plugin (for example,
  `kbs+pkcs11://` for the Trustee `pkcs11` plugin).

When a URI is parsed, `kbs://` and `kbs+resource://` are both stored internally
with plugin name `resource`. When serialized (for example via JSON), the default
`resource` plugin is omitted and the canonical form is `kbs://`.

### Host and Port

The host and port point to the KBS instance that will serve the resource.
Today, the CDH ignores these fields and instead gets the KBS URI and port
from the CDH config file.
This way, the resource URI does not need to be updated if the KBS URI changes.
This means that generally only one KBS serves resources for a pod, there are ways
to work around this with sealed secrets.
Multi-KBS workloads may be supported in the future.

Since these fields are ignored, most resource URIs leave them out.
This results in three slashes in a row.
For example, `kbs:///default/cosign-public-key/test`.

### Resource path (segments)

The path portion of the URI is a sequence of one or more segments separated by
`/`.

A common convention is that `resource` plugin uses three segments — often called `repository`, `type`, and
`tag` — but these names are arbitrary. Any number of segments is valid as long as
the path is non-empty.

When using the Trustee `resource` plugin, the joined segments form the resource
path sent to KBS. Other plugins may interpret the segments differently.

### Query strings

The resource URI supports query strings, which are forwarded to the KBS HTTP
request when present.

## Examples

* `kbs://example.cckbs.org:8081/alice/decryption-key/1`
* `kbs:///a/b/c`
* `kbs+pkcs11:///a/b/c`
* `kbs:///repo/nested/type/tag/extra` (paths with more than three segments)
* `kbs:///repo/type/tag?param1=value1&param2=value2`

After parsing and re-serialization, a URI for the default `resource` plugin is
normalized to the `kbs://` form, for example `kbs:///a/b/c`. URIs with other
plugins keep an explicit plugin in the scheme, for example
`kbs+pkcs11:///a/b/c`.

## Mapping

The resource URI is transformed into an HTTP(S) request to Trustee.
The path segments (everything after the authority) are joined with `/` and
appended after the plugin name:

```plaintext
http://<kbs_host>:<kbs_port>/kbs/v0/<plugin>/<segment1>/<segment2>/...
```

For example, `kbs://example.cckbs.org:8081/alice/decryption-key/1` becomes:

```plaintext
http://example.cckbs.org:8081/kbs/v0/resource/alice/decryption-key/1
```

If no plugin is specified in the resource URI (`kbs://`), `resource` is used.

More information on the KBS API can be found [here](https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs.yaml).
