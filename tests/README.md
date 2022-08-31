# Integration Test for Image-rs

This integration test has 2 main sub-type tests:
* Image decryption using [ocicrypt-rs](https://github.com/confidential-containers/ocicrypt-rs)
* Image signature verification.

## Image Decryption

Implemented in `image_decryption.rs`.

Image decryption will cover both Sample KBC and Offline-fs-kbc:
* Sample KBC uses `"docker.io/arronwang/busybox_kbs_encrypted"`
* Offline-fs-kbc uses `docker.io/xynnn007/busybox:encrypted`

Each test suite will follow these steps:

* Pull manifefst of `"docker.io/arronwang/busybox_kbs_encrypted"` without verification of signature.
* Pull layers of the mentioned image.
* Ocicrypt-rs will ask the Attestation-Agent to decrypt the Layer Encryption Key (LEK for short), which is 
encrypted using Key Encryption Key (KEK for short). KEK is hard-coded in sample-kbc.
* Ocicrypt-rs decrypt the layers using LEK. Finish the image pulling.

The way to genetate KBS encrypted image please refer to
[the guide](https://github.com/confidential-containers/image-rs/blob/main/test_data/generate_test_data.md)

## Image Signature Verification

Implemented in `signature_verification.rs`.

Image Signature Verification includes the following four
tests illustrated in 
<https://github.com/confidential-containers/image-rs/issues/43>,
s.t.

| |signed image|unsigned image|
|---|---|---|
|protected registry|protected_signed_allow, protected_signed_deny|protected_unsigned_deny|
|unprotected registry|-|unprotected_unsigned_allow|

Here
* `signed/unsigned`: Whether this image is signed or unsigned.
* `protected/unprotected`: Whether this image is covered by
any entry (`transports/docker`) in the policy.json. Now it refers to
repository `quay.io/kata-containers/confidential-containers` concretely.
* `allow/deny`: Whether the image to be pulled in this test should be allowed
or denied.

In `signature_verification.rs`, the tests are organized due different kinds
of KBCs, which means for each given KBC, all four tests mentioned will be
covered. We use `rstest` crate to parametrize different KBCs.
