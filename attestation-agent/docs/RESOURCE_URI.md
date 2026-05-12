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
kbs+<plugin>://<kbs_host>:<kbs_port>/<repository>/<type>/<tag>
```

### Scheme

The scheme always begins with `kbs`. Typically the scheme is simply `kbs://`, but a plus sign
can be used to specify that the resource should be fulfilled by a particular plugin.

For instance, to represent a resource fulfilled by the Trustee `pkcs11` plugin, the
scheme would be `kbs+pkcs11://`.

If no plugin is specified, the CDH will request a resource from the `resource` plugin.

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
For example, `kbs:///repository/type/tag`.
 
### Repository, Type, and Tag

Currently resource URIs have three levels of identifiers/scope.
The terms `repository`, `type`, and `tag` are somewhat arbitrary. 
These identifiers can be used in any way.

### Query Strings

The resource URI also supports query strings.

## Examples

* `kbs://example.cckbs.org:8081/alice/decryption-key/1`
* `kbs:///a/b/c`
* `kbs+pkcs11:///a/b/c`

## Mapping

The resource URI is transformed into an HTTP(S) request.
Specifically, the request will be made to `http://<kbs_host>:<kbs_port>/kbs/v0/<plugin>/alice/decryption-key/1`.

If no plugin is specified in the resource URI, `resource` will be used.
More information on the KBS API can be found [here](https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs.yaml).
