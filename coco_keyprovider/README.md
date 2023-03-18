# CoCo Keyprovider

CoCo Keyprovider is a very simple keyprovider tool, which can help to generate CoCo-compatible encrypted images.
The encrypted image can be decrypted using `cc-kbc`, `offline-fs-kbc`, `offline-sev-kbc`, `online-sev-kbc` and `eaa-kbc`.

Also, historical toy KBC `sample kbc` is also supported.

The following guide will help make an encrypted image using CoCo keyprovider and decrypt that.

## Encryption

Build and run CoCo keyprovider.

```
cd attestation-agent/coco_keyprovider
RUST_LOG=coco_keyprovider cargo run --release -- --keyprovider_sock 127.0.0.1:50000
```

vim ocicrypt.conf: 

```
{
    "key-providers": {
        "attestation-agent": {
            "grpc": "127.0.0.1:50000"
        }
    }
}
```

Copy the image you want to encrypt to your current directory. This example uses a *busybox* image:

```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --encryption-key provider:attestation-agent:<parameters> docker://busybox oci:busybox_encrypted
```
After encryption, it can be seen that busybox-encrypted is generated in the current directory.

Or we can directly push the encrypted image to the remote image registry

```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --encryption-key provider:attestation-agent:<parameters> docker://busybox docker://docker.io/myrepo/busybox:encrypted
```

### Parameters

The `<parameters>` in skopeo command is a key-value list separated by double colons. Here are the defined keys:
- `sample`: Not required. Either `true` or `false`. If not set, use `false`. This value indicates whether the hardcoded encryption key is used. This works the same way as `sample keyprovider`.
- `keyid`: Required if `sample` is not enabled. It is a KBS Resource URI, s.t. `kbs://<kbs-addr>/<repo>/<type>/<tag>`. When decryption occurs, the `keyid` value is used to index the KEK.
- `keypath`: Required if `sample` is not enabled. A local filesystem path, absolute path recommended. Specify the KEK to encrypted the image in local filesystem. KEK will be read from fs and then used to encrypt the image. This key's length must be 32 bytes.
- `algorithm`: Not required. Indicate the encryption algorithm used. Either `A256GCM` or `A256CTR`. If not provided, use `A256GCM` by default as it is AEAD scheme.

### Examples

Generate a key to encrypt the image
```bash
head -c32 < /dev/random > key1
```

- Use key of path `key1`, and keyid `kbs:///default/key/key_id1` to encrypt an image. In this way sample is disabled, and will use A256GCM (AES-256-GCM).
```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --insecure-policy --encryption-key provider:attestation-agent:keypath=key1::keyid=kbs:///default/key/key_id1::algorithm=A256GCM docker://busybox oci:busybox:encrypted
```

- Use sample key provider to encrypt an image
```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --insecure-policy --encryption-key provider:attestation-agent:sample=true docker://busybox oci:busybox:encrypted
```

If not sure about whether the image is encrypted, we can export the image to check whether it is encrypted.

In this example, we can find `./busybox/index.json` as following
> **Note** : If the image is pushed to a registry, use skopeo to copy to local first and check.

```json
{
    "schemaVersion": 2,
    "manifests": [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:73135775766027c5006e7744fa8007e812afec905064743c68b780dd49c1eeaf",
            "size": 1195,
            "annotations": {
                "org.opencontainers.image.ref.name": "encrypted"
            }
        }
    ]
}
```
Then we can find the manifest `./busybox/blocs/sha256/73135775766027c5006e7744fa8007e812afec905064743c68b780dd49c1eeaf`
```json
{
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:3488e6e2e41e62fc51be840cd61d806d5b45defdb84a2e6c99ea8a0edb4b6cc7",
        "size": 575
    },
    "layers": [
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
            "digest": "sha256:0dfdc90a4529ca0b38e575945748d6f8258ad2ea2cce8755b8a9f0e1566e447f",
            "size": 2592227,
            "annotations": {
                "org.opencontainers.image.enc.keys.provider.attestation-agent": "eyJraWQiOiJrYnM6Ly8vZGVmYXVsdC90ZXN0LWtleS8xIiwid3JhcHBlZF9kYXRhIjoiLzNMeWhsdVE1aG42MVVjN0ZDM1BWTlNDUlV0YitLc1h5ZWhGTERtaUJlcUE4cStrcGgxbFpwckR4cjh0ck5RUFpxRDB2UlFobVFFWTM1YnV3R05VeGRINXdyeWtCa0x2OTFkSHFHMEJOY1FETVNhNTBBZFpqb00xTHQ0SUdIUDlZeEpGL3hmcWk4RFFBUmdXNjhpV3hlcWgxTFRMQ01hcUg5TzUxeXduYmcxTmJ3aFM0aXdkRSttMGRhOWwyTXpqeklrbjRtN3pWZUl6cFRVVHJuS0gyM1RmWmVWZUZsZVMxY0VscWhGdGw4bnZDYmphNlZyQlFYTzRFVVZUdjkvemxzS2xnRnl3aEhnL1VvUHBmMXMvY2RJPSIsIml2IjoiQUFBQUFBQUFBQUFBQUFBQSIsIndyYXBfdHlwZSI6IkEyNTZHQ00ifQ==",
                "org.opencontainers.image.enc.pubopts": "eyJjaXBoZXIiOiJBRVNfMjU2X0NUUl9ITUFDX1NIQTI1NiIsImhtYWMiOiJqWHhYMGVWWGR2RHAxbVpxSHVXYzFJWGFwazhicmhKMHdpbDl5K3JLUXc4PSIsImNpcGhlcm9wdGlvbnMiOnt9fQ=="
            }
        }
    ]
}
```

We can see that the layer's `mediaType` is `application/vnd.oci.image.layer.v1.tar+gzip+encrypted`, which means the layer is encrypted.

Another way to ensure the image is encrypted is to use offline_fs_kbc to test, which will be described in the following.
## Decryption

Build and run AA: 

```
cd attestation-agent
make KBC=offline_fs_kbc && make install
RUST_LOG=attestation_agent attestation-agent --keyprovider_sock 127.0.0.1:48888
```

Modify ocicrypt.conf: 

```
{
    "key-providers": {
        "attestation-agent": {
            "grpc": "127.0.0.1:48888"
        }
    }
}
```

Ensure the key is recorded in the `/etc/aa-offline_fs_kbc-keys.json`. In the example in [encryption](#encryption), `"kbs:///default/key/key_id1":"<base64-encoded-key>"` should be included in `/etc/aa-offline_fs_kbc-keys.json`.

Decrypt container image: 

```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --insecure-policy --decryption-key provider:attestation-agent:offline_fs_kbc::null oci:busybox:encrypted oci:busybox-decrypted
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
