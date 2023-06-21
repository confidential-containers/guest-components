# CoCo Keyprovider

CoCo Keyprovider is a very simple keyprovider tool, which can help to generate CoCo-compatible encrypted images.
The encrypted image can be decrypted using the following Key Broker Client (KBC):
 * cc-kbc
 * offline-fs-kbc
 * offline-sev-kbc
 * online-sev-kbc
 * eaa-kbc
 * sample kbc (toy KBC still supported for historical reason)

The following guide will help make an encrypted image using [skopeo](https://github.com/containers/skopeo) and CoCo keyprovider, inspect the image as well as decrypt it.

## Encryption

Build and run CoCo keyprovider at localhost on port 50000:

```shell
$ cd attestation-agent/coco_keyprovider
$ RUST_LOG=coco_keyprovider cargo run --release -- --socket 127.0.0.1:50000 &
```

Skopeo leverages the [Ocicrypt](https://github.com/containers/ocicrypt) library to encrypt/decrypt images. Create an [Ocicrypt keyprovider](https://github.com/containers/ocicrypt/blob/main/docs/keyprovider.md) configuration file as shown below and export the `OCICRYPT_KEYPROVIDER_CONFIG` variable:

```shell
$ cat <<EOF > ocicrypt.conf
{
  "key-providers": {
    "attestation-agent": {
      "grpc": "127.0.0.1:50000"
}}}
EOF

$ export OCICRYPT_KEYPROVIDER_CONFIG="$(pwd)/ocicrypt.conf"
```

Use the skopeo's *copy* command to copy the original image and encrypt it. This tool may copy images from/to different storages using various transport protocols (e.g. docker, oci, docker-archive,...etc) but not all storages support encrypted images. Also beware that skopeo will not warn that the image was left unencrypted in case of failure. In our experience, two scenarious will produce a correct encrypted image:
 * copying to oci image on the current directory
 * copying directly to a remote image registry using the docker protocol, as long as the destination registry support encrypted images. Examples of image registry services that support encrypted images are [docker.io](https://docker.io) and [ghcr.io](https://ghcr.io).

The following example copy *busybox* and encrypt to *busybox_encrypted* image in the current directory:

```shell
$ skopeo copy --insecure-policy --encryption-key provider:attestation-agent:<parameters> docker://busybox oci:busybox_encrypted
```

Or we can directly push the encrypted image to the remote image registry:

```shell
$ skopeo copy --insecure-policy --encryption-key provider:attestation-agent:<parameters> docker://busybox docker://docker.io/myrepo/busybox:encrypted
```

On the examples above the `--insecure-policy` option is not needed for encryption, it only disables the system's trust policy to avoid any errors with image validation, so it can be ommitted if your system's policy is properly configured. The `--encryption-key` specifies the encryption protocol that will be explained on the next section.

### The encryption protocol explained

As shown on the previous section, the encryption protocol (`--encryption-key`) passed to skopeo has the `provider:attestation-agent:<parameters>` format.

The `<parameters>` is a key-value list separated by double colons (e.g. key1=value1::key2=value2). Here are the defined keys:
- `sample`: Not required. Either `true` or `false`. If not set, use `false`. This value indicates whether the hardcoded encryption key is used. This works the same way as `sample keyprovider`.
- `keyid`: Required if `sample` is not enabled. It is a Key Broker Service (KBS) Resource URI (see the specification below). When decryption occurs, the `keyid` value is used to index the Key Encryption Key (KEK).
- `keypath`: Required if `sample` is not enabled. A local filesystem path, absolute path recommended. Specify the KEK to encrypt the image in local filesystem. KEK will be read from filesystem and then used to encrypt the image. This key's length must be 32 bytes.
- `algorithm`: Not required. Indicate the encryption algorithm used. Either `A256GCM` or `A256CTR`. If not provided, use `A256GCM` by default as it is AEAD scheme.

The `keyid` parameter refers an KBS Resource URI and must follow one of the following formats,
- `kbs:///<repository>/<type>/<tag>`
- `kbs://<kbs-addr>/<repository>/<type>/<tag>`
- `<kbs-addr>/<repository>/<type>/<tag>`
- `/<repository>/<type>/<tag>`

Where:
- `kbs-addr`: is the `address[:port]` of the KBS
- `repository`: is the resource's repository (e.g. docker.io)
- `type`: is the resource type (e.g. key)
- `tag`: is the resource tag or identifier (e.g. key\_id1)

### Examples

This section contain encrypting examples.

#### Example 1: encrypting for sample kbc

Let's start with the simplest example possible, which is to encrypt an image using the sample key provider:

```shell
$ skopeo copy --insecure-policy --encryption-key provider:attestation-agent:sample=true docker://busybox oci:busybox_encrypted:sample
```

#### Example 2: encrypting for Offline fs, Offline SEV and Online SEV KBC

For `offline-fs-kbc`, `offline-sev-kbc` and `online-sev-kbc` the KBS address is ommitted and the encryption key created upfront. This key can be then provisioned in a KBS as, for example, on the [simple-kbs](https://github.com/confidential-containers/simple-kbs) for `online-sev-kbc`.

So create a random 32-bytes key file:

```shell
$ head -c32 < /dev/random > key1
```

Use key of path `key1`, and keyid `kbs:///default/key/key_id1` to encrypt an image. In this way sample is disabled, and will use A256GCM (AES-256-GCM):

```shell
$ skopeo copy --insecure-policy --encryption-key provider:attestation-agent:keypath=$(pwd)/key1::keyid=kbs:///default/key/key_id1::algorithm=A256GCM docker://busybox oci:busybox_encrypted:default
```

### Inspecting the image

If not sure about whether the image is encrypted, we can export the image to check whether it is encrypted.

The examples one and two of the previous section, we can find the OCI image in the `busybox` directory at the current directory.

> **Note** : If the image is pushed to a registry, use the "docker://" transport protocol instead on the examples below.

You can use skopeo's *inspect* command to print low-level information of the image:

```bash
$ skopeo inspect oci:busybox_encrypted:default
{
    "Digest": "sha256:28d649e5c1fb00b5a2cfdc8a0e95057a17addf80797ce2a6b45d89964b35b968",
    "RepoTags": [],
    "Created": "2023-05-11T22:48:43.533857581Z",
    "DockerVersion": "",
    "Labels": null,
    "Architecture": "amd64",
    "Os": "linux",
    "Layers": [
        "sha256:4d7ebe01f6574c525dc52ad6506d19aac1ad14eb783955cc1df93fda14073ae1"
    ],
    "LayersData": [
        {
            "MIMEType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
            "Digest": "sha256:4d7ebe01f6574c525dc52ad6506d19aac1ad14eb783955cc1df93fda14073ae1",
            "Size": 2590751,
            "Annotations": {
                "org.opencontainers.image.enc.keys.provider.attestation-agent": "eyJraWQiOiJrYnM6Ly8vZGVmYXVsdC9rZXkva2V5X2lkMSIsIndyYXBwZWRfZGF0YSI6IjNFZ1FidzZDUlY0YmlrMnNLM3RrTUpweWNWV0RVZXVIY1luZ1drZFd1K0swQXpDUGY3dFlCQ1oxSGxXaWFsZmdFdEQxdDBuc3N2YS81aElFbUxPbXZjYXJ2SGlNdERyRElhY1JIdElOTHFyUUpCZUY1M2Q4MTN1L0dDK3prL3RHeEF3ZVd6ZTR1S0VROG1qc2hyMytiYll3RUhKdVFyM3VncWlXRTlnNUhndU1HVmVFZ2ZReWR2dS9TZmVYMmZSeTRQWmtGcjhWbkQ3WjRrNUhXVkhaTWY0U21oSUhhUnlVa1NoT3B4dVdQcG54OW9IaGJSMEdKd2Zwb3l4TzRydEpYaTI4ODVxZ1Uya0dVaFo2RTJTbmgrQT0iLCJpdiI6IjRlekxiZU1RZEVrWS9pdUYiLCJ3cmFwX3R5cGUiOiJBMjU2R0NNIn0=",
                "org.opencontainers.image.enc.pubopts": "eyJjaXBoZXIiOiJBRVNfMjU2X0NUUl9ITUFDX1NIQTI1NiIsImhtYWMiOiJQM08rQ1lhRGNSNkJteEpvdWlFV0lYM05XN1l2Nk5UcEp5dmhlNlBmbFA4PSIsImNpcGhlcm9wdGlvbnMiOnt9fQ=="
            }
        }
    ],
    "Env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ]
}
```

We can see that the layer's `MIMEType` is `application/vnd.oci.image.layer.v1.tar+gzip+encrypted`, which means the layer is encrypted.

The `org.opencontainers.image.enc.keys.provider.attestation-agent` layer's annotation contains (base64 encoded) the used encryption parameters, and `org.opencontainers.image.enc.pubopts` the cipher options. Those are used by the kbc on the decryption process.

You can inspect content of the layer's annotations as:

```bash
$ skopeo inspect oci:busybox_encrypted:default | jq -r '.LayersData[].Annotations."org.opencontainers.image.enc.keys.provider.attestation-agent"' | base64 -d
{"kid":"kbs:///default/key/key_id1","wrapped_data":"3EgQbw6CRV4bik2sK3tkMJpycVWDUeuHcYngWkdWu+K0AzCPf7tYBCZ1HlWialfgEtD1t0nssva/5hIEmLOmvcarvHiMtDrDIacRHtINLqrQJBeF53d813u/GC+zk/tGxAweWze4uKEQ8mjshr3+bbYwEHJuQr3ugqiWE9g5HguMGVeEgfQydvu/SfeX2fRy4PZkFr8VnD7Z4k5HWVHZMf4SmhIHaRyUkShOpxuWPpnx9oHhbR0GJwfpoyxO4rtJXi2885qgU2kGUhZ6E2Snh+A=","iv":"4ezLbeMQdEkY/iuF","wrap_type":"A256GCM"}
$ skopeo inspect oci:busybox_encrypted:default | jq -r '.LayersData[].Annotations."org.opencontainers.image.enc.pubopts"' | base64 -d
{"cipher":"AES_256_CTR_HMAC_SHA256","hmac":"P3O+CYaDcR6BmxJouiEWIX3NW7Yv6NTpJyvhe6PflP8=","cipheroptions":{}}
```

Another way to ensure the image is encrypted is to use offline_fs_kbc to test, which will be described in the following section.

## Decryption

Let's show how the image created on [example two](#example-2-encrypting-for-offline-fs-offline-sev-and-online-sev-kbc) can be decrypted.

Build and run Attestation Agent (AA) at localhost on port 48888:

```shell
$ cd attestation-agent
$ make KBC=offline_fs_kbc && make DESTDIR="$(pwd)" install
$ RUST_LOG=attestation_agent ./attestation-agent --keyprovider_sock 127.0.0.1:48888 &
```

Create a new ocicrypt.conf and re-export OCICRYPT_KEYPROVIDER_CONFIG:

```shell
$ cat <<EOF > ocicrypt.conf
{
  "key-providers": {
    "attestation-agent": {
      "grpc": "127.0.0.1:48888"
}}}
EOF
$ export OCICRYPT_KEYPROVIDER_CONFIG="$(pwd)/ocicrypt.conf"
```

Ensure the key is recorded in the `/etc/aa-offline_fs_kbc-keys.json`. In the example two in [encryption](#encryption), `"default/key/key_id1":"<base64-encoded-key>"` should be included in `/etc/aa-offline_fs_kbc-keys.json`:

```shell
$ cd attestation-agent/coco_keyprovider
$ ENC_KEY_BASE64="$(cat key1 | base64)"
$ cat <<EOF > aa-offline_fs_kbc-keys.json
{
  "default/key/key_id1": "${ENC_KEY_BASE64}"
}
EOF
$ sudo cp aa-offline_fs_kbc-keys.json /etc/
```

Decrypt the image:

```shell
$ skopeo copy --insecure-policy --decryption-key provider:attestation-agent:offline_fs_kbc::null oci:busybox_encrypted:default oci:busybox_decrypted
```

The decrypted image should have the layers's `MIMEType` equal to `application/vnd.oci.image.layer.v1.tar+gzip` as:

```shell
$ skopeo inspect oci:busybox_decrypted | jq -r '.LayersData[].MIMEType'
application/vnd.oci.image.layer.v1.tar+gzip
```

## Related tools

### Test Key Generation and Offline-Fs-KBC

`tools/generate_keys.sh` is a helper script to generate ten different base64-encoded KEK. Also, it can help to generate the `aa-offline_fs_kbc-keys.json` used by offline-fs-kbc.
**Warning**: `jq` is required, so please install jq before use the script. For example on ubuntu, `apt install jq` could help.

#### Generate `aa-offline_fs_kbc-keys.json`

```bash
tools/generate_keys.sh generate > aa-offline_fs_kbc-keys.json
```

you will get a randomly generated `aa-offline_fs_kbc-keys.json` like the following
```
{
  "default/key/key_id7": "gH4b2MYb/lGrYRVmrf3qtNo46mzC6C87cN5hdRt+Wvg=",
  "default/key/key_id6": "cemWcxJw9fG11Y3WhrzcZNKBWebdFt7qQDsIa6h6kJI=",
  "default/key/key_id10": "FePQCdgX/UONTIOl6eQP+7Itq5fdwr8JPufkmypbMWI=",
  "default/key/key_id5": "uDAikSR/Hadk7RXkA86DBsQs8eekP/dkLkXyuVjyLf8=",
  "default/key/key_id4": "5PN33vLpX+UO82Ryl/BhZNm5+suhTrBEqdWTDi1wqVU=",
  "default/key/key_id3": "Y8ptYp5WgJxXdhe5tIS+ZIoSlVup1DUHu63MyHOsxsA=",
  "default/key/key_id2": "sIDb9K+J7IEfYQMbcDzEYz8t+hABQlHSR+55SIAgsUw=",
  "default/key/key_id1": "TfyYGL/gBbtXwgDmx3a6N6WxFJFamcSRUFlpBPXu0f4=",
  "default/key/key_id9": "CfGZPsmKq1pkzraBpMAsbBZGIGlbWUepu4eR/Z4exnE=",
  "default/key/key_id8": "eXIlv83nTjfyeLZcCvTda9ypYIYj83eGjbqjoVFAQHA="
}
```

#### Use the Generated Key to Encrypt Image

If we want to use key of id `default/key/key_id1` in `aa-offline_fs_kbc-keys.json` to encrypt an image, we firstly export the key content to file `key1`

```
tools/generate_keys.sh export aa-offline_fs_kbc-keys.json default/key/key_id1 key1
```

> **Warning** : As in current code we do not actually use the `<kbs-addr>` in a KBS Resource URI. When using skopeo to encrypt the image, we can specify the `keyid` in format `kbs:///<repo>/<type>/<tag>`, e.g. `kbs:///default/key/key_id1`.
