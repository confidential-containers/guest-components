# Signature Module for Image-rs

This is the signature module for image-rs. In fact, signature verification
is included in the policy processing.

## How is signature verification working?

Up to now, all signature verification in image-rs happens due to
the image security [policy](https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#policy) 
file.

The format of policy file is detailed [here](../docs/ccv1_image_security_design.md#policy).

Each signing scheme works due to the `scheme` field in a [Policy Requirement](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements).

The format of a Policy Requirement may be little different from the mentioned link.

A Policy Requirement claiming a specific signature scheme in the `scheme` field.
Here are some examples for [Simple Signing](src/mechanism/simple/README.md)

```json
{
    "type": "signedBy",
    "scheme": "simple",
    "keyType": "GPGKeys",
    "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
}
```

Here, the `type` field here must be `signedBy` if this Policy Requirement
requires signature verification. And the `scheme` field will indicate
the concrete signing scheme for this Policy Requirement. The rest of the 
fields may be different due to different signing scheme. 

For example,
[Simple Signing](src/mechanism/simple/README.md) here requires fields
`keyType`, `keyPath`, `keyData`, and `signedIdentity`.

## How to add new Signing Scheme?

For example, a new scheme called `new-sign-scheme` is to be added.
Here are the positions must be modified.

1. `src/mechanism/new-sign-scheme` directory
Create `src/mechanism/new-sign-scheme/mod.rs`

Add `pub mod new_sign_scheme` into  `src/mechanism/mod.rs`

In `src/mechanism/new-sign-scheme/mod.rs`, define the unique parameters 
used in the `policy.json` by `new-sign-scheme`.
For example, a field named `signature-path` should be included, like

```json
// ... A Policy Requirement
{
    "type": "signedBy",
    "scheme": "new-sign-scheme",
    "signature-path": "/keys/123.key",
}
```

Then the parameters' struct can be defined in `src/mechanism/new-sign-scheme/mod.rs`,
like this

```rust
#[derive(Deserialize, Debug, PartialEq, Serialize)]
pub struct NewSignSchemeParameters {
    #[serde(rename = "signature-path")]
    pub signature_path: String,
}
```
And then the field can be deserialized from `policy.json`.

Besides, Implement the public function `some_verify_function()`. This is the core
function for `new-sign-scheme` to verify signatures.

2. `src/mechanism/mod.rs`.

Add a new enum value `NewSignScheme` for `SignScheme` in 

```rust
pub enum SignScheme {
    #[serde(rename = "simple")]
    SimpleSigning(SimpleParameters),
    // Here new scheme
    #[serde(rename = "new-sign-scheme")]
    NewSignScheme(NewSignSchemeParameters),
}
```

Fill in the new arm in the following function. 
```rust
pub fn allows_image(&self, image: &mut Image) -> Result<()> {
        match self {
            SignScheme::SimpleSigning(parameters) => {
                simple::judge_signatures_accept(&parameters, image)
            }
            // New arm
            SignScheme::NewSignScheme(parameters) => {
                new_sign_scheme::some_verify_function(&parameters, image)
            }
        }
    }
```

Here, `some_verify_function` is the signature's verifier function
implemented in step 1.

## Supported Signatures

|Sign Scheme|Readme|
|---|---|
|[Simple Signing](src/mechanism/simple)| - |