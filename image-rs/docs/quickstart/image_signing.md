# Image signing with cosign

This document includes the following:
* Guide to generate a cosign-signed image.
* Guide to config image security policy to enable signature verification of the image.
* Guide to distribute the public key and image security policy via offline-fs-kbs.

## Signing the encrypted/unencrypted image and enable signature verification when running the workload

When an image is being pulled from a container registry, [policy requirements](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements)
can determined whether the image can be accepted.

The requirements can be:

* Directly reject
* Unconditional accept
* Signature verification required

This section shows how to sign an image, and enable signature verification of specific repository.

### Signing an image with cosign

Both encrypted and unencrypted image can be signed.

We need to install `cosign` to sign images. Detailed work process behind `cosign` can be found in [this doc](../../src/signature/policy/cosign/README.md).
Follow [the guide here](https://github.com/sigstore/cosign#installation) to install `cosign`:

After installing `cosign`, we need to generate a key pair to sign images and verify related signatures.

```
# Generate signing key pair
cosign generate-key-pair
```

After typing a password twice, a key pair will be generated, s.t. private key `cosign.key` and public key `cosign.pub`. 
Here, the password is used to encrypt the private key. 
When we use the private key to sign an image, the password is required. Of cource, the password can be empty.

Suppose there is already an image prepared to be signed named `example.org/test`:

```
# sudo docker images
REPOSITORY            TAG                  IMAGE ID       CREATED         SIZE
example.org/test      latest               ff4a8eb070e1   2 weeks ago     1.24MB
```
Now let us sign this image with the newly generated private key

```
cosign sign --key cosign.key [REGISTRY_URL]:cosign-signed
```

Here, `cosign.key` can be replaced with any cosign-generated private key.

Now the image is signed by cosign, and the signature is pushed to the same repository as the image.

To learn more about cosign, please refer to [the github repository](https://github.com/sigstore/cosign).

### Enable cosign image signature verification and retrieve public key via KBC channel

Take the `offline_fs_kbc` KBC provided by [Confidential Data Hub](../../../confidential-data-hub/docs/RESOURCES_SERVICES.md) (Offline-FS-KBC for short) for example.

#### Prepare Confidential Data Hub (CDH) with Offline-Fs-KBC

Clone the repository.

```
git clone https://github.com/confidential-containers/guest-components
```

Build CDH, disabling KMS providers to speed up the build (`offline_fs_kbc` is always built in):
```
cd guest-components/confidential-data-hub
make KMS_PROVIDER=none
```

#### Add Offline-Fs-KBC resources

All signature verification rules are defined in a `policy.json`. But before we work on
the `policy.json`, there are a few things to be clarified:
* The `policy.json` is provided by the relying party, so we will use Offline-Fs-KBC to provide
this secret file. The channel is secure.
* The verification public key is also retrieved via KBC secure channel.

So the next steps will firstly add the two resources (`policy.json` and public key) to the
Offline-Fs-KBC resources.

Let's continue with the image `example.org/test`, and enable security strategy (including signature verification).

Firstly edit an `policy.json` like

```
{
    "default": [{"type": "reject"}], 
    "transports": {
        "docker": {
            "example.org": [
                {
                    "type": "sigstoreSigned",
                    "keyPath": "/run/image-security/cosign/cosign.pub"
                }
            ]
        }
    }
}
```

Here, `"keyPath"` refers to the path to the `cosign.pub` public key. When verification
occurs, firstly the path is checked to see whether there is such a file. If not, the
key will be retrieved via the KBC secure channel.

let's calculate base64-encoded values for the two resources
```bash
cat /path/to/policy.json | base64 --wrap=0
cat /path/to/cosign.pub | base64 --wrap=0
```

`offline_fs_kbc` reads resources from `/etc/aa-offline_fs_kbc-resources.json`. Add the two
resources' base64-encoded values there under keys `default/security-policy/test` (policy) and
`default/cosign-public-key/test` (public key), e.g.

```
{
  "default/security-policy/test": "<base64-encoded policy.json>",
  "default/cosign-public-key/test": "<base64-encoded cosign.pub>"
}
```

Then install the file, along with an (empty, if unused) keys file:
```
sudo cp aa-offline_fs_kbc-resources.json /etc/aa-offline_fs_kbc-resources.json
sudo cp aa-offline_fs_kbc-keys.json /etc/aa-offline_fs_kbc-keys.json
```

In this way, when the images from `"example.org"` is being pulled,
the signature will be verified using the public key of path `"/run/image-security/cosign/cosign.pub"`.

Now let's start CDH, configured to serve `offline_fs_kbc` resources over ttRPC/gRPC (see
[Confidential Data Hub docs](../../../confidential-data-hub/docs/RESOURCES_SERVICES.md) for a full
config example):

```
confidential-data-hub -c cdh_conf.toml
```

Now the confidential-data-hub can respond with the correct resources to image-rs's resource
provider (which connects to CDH over ttRPC/gRPC, see [`image-rs/src/resource/kbs`](../../src/resource/kbs)).
