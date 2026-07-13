# Registry Configuration

## Backgrounds

The CONTAINERS-REGISTRIES configuration file is a configuration file for container image registries.

It can provide blocking, remapping and mirroring functions based on the registry/repo/image level.

> [!NOTE]
> This configuration will be applied before [image security policy](./ccv1_image_security_design.md).

### Related Links

- [Syntax of Container Registries Configuration](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md)
- [How to manage Linux container registries](https://www.redhat.com/en/blog/manage-container-registries)

## Example

The path to the configuration file can be set via `image-rs`'s configuration's `registry_configuration_uri`.
Its format looks like

```toml
# handle short name
unqualified-search-registries = ["docker.io", "example1.com"]

# block registries
[[registry]]
prefix = "example.com/banned"
blocked = true

# registry mirror
[[registry]]
prefix = "example.com/foo"
insecure = false
blocked = false

[[registry.mirror]]
location = "example-mirror-0.local/mirror-for-foo"

[[registry.mirror]]
location = "example-mirror-1.local/mirrors/foo"
insecure = true

# registry remapping
[[registry]]
prefix = "registry.com"
location = "remapping.registry.com"

# allow insecure registry
[[registry]]
location = "localhost:5000"
insecure = true
```

Let's go through the usages by some typical scenarios.

## Typical Usages

### Pulling images by short names

Usually when we use kubernetes or docker, we don’t specify the complete registry and repository path
of the image. By default, it will be downloaded from `docker.io`. A `docker pull alpine` will resolve
to `docker.io/library/alpine:latest`, and docker pull `repo/image:tag` will resolve to `docker.io/repo/image:tag`
(notice the specified repo).

So if we want the short name to be resolved to more registries, we can use the `unqualified-search-registries`.

```toml
unqualified-search-registries = ["docker.io", "example1.com"]
```

An image with `alpine` will be resolved to `docker.io/library/alpine:latest` and `example1.com/alpine:latest`.
An image with `repo/alpine` will be resolved to `docker.io/repo/alpine:latest` and `example1.com/repo/alpine:latest`.
Note that registry `docker.io` will automatically add a namespace `library` if the image name is not qualified.

### Blocking a registry, namespace or a image

If a registry is not allowed to be used, we can use the `blocked` field to block it.

```toml
[[registry]]
prefix = "example.com/banned"
blocked = true
```

The `blocked=true` prevents image pullings with this prefix, e.g. `example.com/banned/repo:tag`.

If a specific image is to be blocked, the `prefix` can set it using the following:

```toml
prefix="registry.example.org/namespace/image"
```

### Mirroring registries

We often pull images in an isolated network environment. In this case, we cannot connect to the
original registry or the network is slow, so we need to run a registry that mirrors the local
network's contents to accelerate the network access.

A registry mirror will be firstly tried before the original registry. If all the mirror pullings
fail, the original registry will be tried.

```toml
[[registry]]
location="registry.access.redhat.com"
[[registry.mirror]]
location="internal.registry.mirror"

[[registry]]
location="docker.io"
[[registry.mirror]]
location="123456.mirror.aliyuncs.com"
```

This time `registry.access.redhat.com/nginx:latest` will be mirrored to `internal.registry.mirror/nginx:latest`.
Similarly, `nginx:latest` will be mirrored to `123456.mirror.aliyuncs.com/library/nginx:latest` and
`foo/bar:latest` will be mirrored to `123456.mirror.aliyuncs.com/foo/nginx:latest`.

### Remapping references

In the mirror scenario, the original repository will still be tried at the end, but remapping redirects the
original image pull request to the new registry. let's consider that we run in an air-gapped environment.
We cannot access container registries since we are disconnected from the internet. Our workload is using images
from `Quay.io`, `Docker Hub`, and Red Hat's container registry. While we could have one network-local mirror
per registry, we could also just use one with the following config.

```toml
[[registry]]
prefix="quay.io"
location="internal.registry.mirror/quay"

[[registry]]
prefix="docker.io"
location="internal.registry.mirror/docker"

[[registry]]
prefix="registry.access.redhat.com"
location="internal.registry.mirror/redhat"
```

### Insecure registry

Running a local container registry is quite common. That implies connecting to the registry via HTTP rather
than via HTTPS. This can be achieved by setting the `insecure` field to `true`.

```toml
[[registry]]
location = "localhost:5000"
insecure = true
```