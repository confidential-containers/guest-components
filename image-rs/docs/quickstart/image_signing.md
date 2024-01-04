# Image signing with cosign

This document includes the following:
* Guide to generate a cosign-signed image.
* TODO: Guide to config image security policy to enable signature verification of the image.

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

We need to install `cosign` to sign images. Detailed work process behind `cosign` can be found in [this doc](../../src/signature/mechanism/cosign).
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
