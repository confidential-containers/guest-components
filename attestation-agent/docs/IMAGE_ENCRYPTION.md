# Image Encryption & Decryption

## Introduction

As stated in [CCv0 image security design](../../image-rs/docs/ccv1_image_security_design.md), CoCo uses image encryption machanism compatible with [ocicrypt](https://github.com/containers/ocicrypt) and [ocicrypt-rs](../../ocicrypt-rs).

Attestation-Agent as a [Key Provider](../../image-rs/docs/ccv1_image_security_design.md#update-manifest) implements API `unwrapkey`, which works together
with the [Sample Key Provider](../coco_keyprovider/) who implements API `wrapkey`.

This document will describe how Attestation-Agent and Sample Key Provider play a role in image encryption. Together, some specifications will also be defined.

## Image Encryption and Decryption

### Encryption

`wrapkey` API is directly related to image encryption. Let's see how image encryption occurs, for example, in `ocicrypt-rs`. The principle behind `ocicrypt` is the same.
Suppose there is a user wanting to encrypt an image layer `L`.

1. `ocicrypt-rs` randomly [generates a symmetric key](../../ocicrypt-rs/src/blockcipher/mod.rs#L167). This key is called LEK (Layer Encryption Key, the key to encrypt the layer).
2. `L` [gets encrypted by the LEK](../../ocicrypt-rs/src/blockcipher/mod.rs#L169)
3. The symmetric key together with other private information is contained in a struct named `PrivateLayerBlockCipherOptions`, s.t. [PLBCO](https://github.com/opencontainers/image-spec/pull/775/commits/bc0fcd698946be7e8bb1fa88f178ed2c66274aa2#diff-ecf63e7090e873922f62c4749c01f63f7eccd42912c1465fbee515cb7c4916c1R362).
4. the plaintext of `PLBCO` will be sent over the gRPC call `wrapkey` to Sample Key Provider. Up to now, the step 1, 2, 3, 4 are standard behavior defined in `ocicrypt`. Then how to perform
`wrapkey` API for Sample Key Provider is defined by CoCo, as to be mentioned in 5, 6.
5. Sample Key Provider will encrypt the `PLBCO`, and generates a struct named `AnnotationPacket`. A `AnnotationPacket` contains
    * `wrapped data`, the ciphertext of the `PLBCO`
    * the `wrap type`, s.t. the encryption scheme used to encrypt the `PLBCO`. The specification of this field will be stated in [section specs](#specs).
    * `iv` of this encryption
    * `key id`, s.t. the identity of the key used to encrypt the `PLBCO`. This key is also called `KEK` (Key Encryption Key, s.t. the key to encryption LEK).
6. The `AnnotationPacket` will be returned to `ocicrypt-rs` and `ocicrypt-rs` will include the base64-encoded (Standard) `AnnotationPacket` in the encrypted layer's annotation with key `org.opencontainers.image.enc.keys.provider.attestation-agent`.

### Decryption

`unwrapkey` API is directly related to image decryption. An image layer encrypted by `Sample Key Provider` can be decrypted with `Attestation-Agent`'s participation.
Here are the steps.
1. `ocicrypt-rs` finds `L` is a encrypted layer, and `L` has a `org.opencontainers.image.enc.keys.provider.attestation-agent` annotation.
2. `ocicrypt-rs` will send the content of the value of `org.opencontainers.image.enc.keys.provider.attestation-agent` annotation over `unwrapkey` gRPC to `Attestation-Agent`.
3. `Attestation-Agent` will parse the annotation into an `AnnotationPacket`.
4. `Attestation-Agent` will use the `AnnotationPacket` to call related KBC's `decrypt_payload()` api to retrieve the `PLBCO`.
    * For `*_sev_kbc`, `offline_fs_kbc`, `get_key()` helps to get the `KEK` due to the `key id`, and then `crypto` module decrypts the PLBCO.
    * For `eaa_kbc` and those KBCes who do not expose the plaintext of the `KEK`, `decrypt_payload()` api will perform its own decryption action.
7. `ocicrypt-rs` uses `PLBCO` to decrypt the layer.

## Specs

This section gives some specification of CoCo involved image encryption/decryption.

### Layer Annotation

As stated [in ocicrypt](https://github.com/opencontainers/image-spec/pull/775/commits/bc0fcd698946be7e8bb1fa88f178ed2c66274aa2#diff-ecf63e7090e873922f62c4749c01f63f7eccd42912c1465fbee515cb7c4916c1R423), a specified protocol to decrypt `PLBCO` should have an annotation key-value pair in the image layer's [OciDescriptor](https://github.com/opencontainers/image-spec/blob/main/descriptor.md) of the image's [manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md).

In CoCo scenerios, the annotation's key should be `org.opencontainers.image.enc.keys.provider.attestation-agent`. This indicates that the image layer can be decrypted by calling `unwrapkey` api of `attestation-agent`.

### Annotation Packet

An `Annotation Packet` is the value of `org.opencontainers.image.enc.keys.provider.attestation-agent` annotation of the encrypted layer's [OciDescriptor](https://github.com/opencontainers/image-spec/blob/main/descriptor.md) (the value is standard-base64-encoded). The format of `Annotation Packet` influences
* How CoCo's Key Provider wrap the LEK.
* How AA unwrap the LEK.
* How different KBCes can be compatible with each other.

We define the format of `Annotation Packet` as following
```json
{
    "kid": "<identity of the KEK>",
    "wrapped_data": "<encrypted LEK (standard-base64-encoded)>",
    "iv": "<initialisation vector for the encryption scheme (standard-base64-encoded)>",
    "wrap_type": "<encryption scheme used to encrypt LEK>"
}
```

### Decryption Interface

Once an `Annotation Packet` is given, the AA can dispatch specified KBC to handle.
For those KBCeswho can retrieve the plaintext of KEK via `key id`, AA can perform decryption operation
with the `KEK`, `wrapped_data`, `iv` and `wrap_type`. This function is provided in `src/crypto`.

Different wrap types share a common decryption interface, s.t.
```rust
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
```

here,
* `key` is `KEK`
* `iv` is `iv`
* `encrypted_data` is `wrapped_data`

We can overload some of the parameters in specific scheme (like we use `iv` as `nonce` in `aes-256-gcm`).

### Wrap Type

Wrap Type is a field in [`Annotation Packet`](#annotation-packet), it tells what encryption/decryption scheme is used.
Fow now, we support the following schemes:
* `A256GCM`: AES with 256-bit key length in Galois Counter Mode. To reuse of the `decrypt` api, we agree that
    * `wrapped_data := ciphertext | Tag`. `Tag` is authentication tag and is 16 bytes in `aes-256-gcm`.
    * The `iv` field actually works as `nonce`.
* `A256CTR`: AES with 256-bit key length in CTR mode.

### OpenSSL Support

By default, decryption depends on Rust implementations.
To make use of hardware acceleration on more platforms (e.g. s390x). OpenSSL is used to implement the encryption/decryption process.
To enable OpenSSL, users can turn on the feature `openssl` to compile.
