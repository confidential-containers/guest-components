# Signature Module for Image-rs

This is the signature module for image-rs. In fact, signature verification
is included in the policy processing.

## How is signature verification working?

Up to now, all signature verification in image-rs happens due to
the image security [policy](../../docs/ccv1_image_security_design.md#policy) 
file.

The format of policy file is detailed [here](../../docs/ccv1_image_security_design.md#policy).

Whether the policy requirement is a signing scheme and which signing scheme it is due to the `type` field in the
[Policy Requirement](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#policy-requirements).

Here are some examples for [Simple Signing](mechanism/simple/README.md)

```json
{
    "type": "signedBy",
    "keyType": "GPGKeys",
    "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release",
}
```

Here, the `signedBy` type shows that this Policy Requirement
is a Simple Signing requirement. The rest of the 
fields may be different due to different signing scheme. 

For example,
[Simple Signing](mechanism/simple/README.md) here requires fields
`keyType`, `keyPath`, `keyData`, and `signedIdentity`.

## How to add new Signing Scheme?

For example, a new scheme called `new-sign-scheme` is to be added.
Here are the positions must be modified.

### `mechanism/new-sign-scheme` directory
Create `mechanism/new-sign-scheme/mod.rs`

Add `pub mod new_sign_scheme` into  `mechanism/mod.rs`

In `mechanism/new-sign-scheme/mod.rs`, define the unique parameters 
used in the `policy.json` by `new-sign-scheme`.
For example, a field named `signature-path` should be included, like

```json
// ... A Policy Requirement
{
    "type": "newSignScheme",
    "signature-path": "/keys/123.key",
}
```

Then the parameters' struct can be defined in `mechanism/new-sign-scheme/mod.rs`,
like this

```rust
#[derive(Deserialize, Debug, PartialEq, Serialize)]
pub struct NewSignSchemeParameters {
    #[serde(rename = "signature-path")]
    pub signature_path: String,
}
```

Besides, Implement the trait `SignScheme` for `NewSignSchemeParameters`.
```rust
/// The interface of a signing scheme
#[async_trait]
pub trait SignScheme {
    /// Do initialization jobs for this scheme. This may include the following
    /// * preparing runtime directories for storing signatures, configurations, etc.
    /// * gathering necessary files.
    async fn init(&self) -> Result<()>;

    /// Judge whether an image is allowed by this SignScheme.
    async fn allows_image(&self, image: &mut Image) -> Result<()>;
}
```

The basic architecture for signature verification is the following figure:

```plaintext
                +-------------+
                | ImageClient |
                +-------------+
                       |
                       | allows_image(image_url,  image_digest, aa_kbc_params)
                       v
              +-----------------+   gRPC Client
              |      Agent      | ---------------> KBS
              +-----------------+    Access
                       |
                       |
      +----------------+-----------------+
      |                                  |
      |                                  |
+-----+-------+                   +------+------+
|   Signing   |                   |   Signing   |
|    Scheme   |                   |    Scheme   |
|   Module 1  |                   |   Module 2  |
+-------------+                   +-------------+
```

When a `ImageClient` need to pull an image, it will call
`allows_image`. `allows_image` will instanialize
a `Agent` to handle Policy Requirements if needed.
The `Agent` can communicate with KBS to retrieve needed
resources. Also, it can call specific signing scheme verification
module to verify a signature due to the Policy Requirement in
`policy.json`. So there must be three interfaces for a signing
scheme to implement:
1. `init()`: This function is called for every signing scheme
policy requirement, so it should be **idempotent**.
It can do initialization work for this scheme. This may include the following
* preparing runtime directories for storing signatures, configurations, etc.
* gathering necessary files.

2. `allows_image()`: This function will do the verification. This
function will be called on every check for a Policy Requirement of this signing scheme.

### `policy/policy_requirement.rs`

Because every signing scheme for an image is recorded in
a policy requirement, we should add here.
Add a new enum value `NewSignScheme` for `PolicyReqType` in 

```rust
pub enum PolicyReqType {
    ...

    /// Signed by Simple Signing
    #[serde(rename = "signedBy")]
    SimpleSigning(SimpleParameters),

    /// Signed by new sign scheme
    #[serde(rename = "newSignScheme")]
    NewSignScheme(NewSignSchemeParameters),
}
```

Here, `NewSignSchemeParameters` must be inside the enum.

Add new arm in the `allows_image` function. 
```rust
pub async fn allows_image(&self, image: &mut Image) -> Result<()> {
    match self {
        PolicyReqType::Accept => Ok(()),
        PolicyReqType::Reject => Err(anyhow!(r#"The policy is "reject""#)),
        PolicyReqType::SimpleSigning(inner) => inner.allows_image(image).await,
        PolicyReqType::NewSignScheme(inner) => inner.allows_image(image).await,
    }
}
```

Add new arm in the `try_into_sign_scheme` function.
```rust
pub fn try_into_sign_scheme(&self) -> Option<&dyn SignScheme> {
    match self {
        PolicyReqType::SimpleSigning(scheme) => Some(scheme as &dyn SignScheme),
        PolicyReqType::NewSignScheme(scheme) => Some(scheme as &dyn SignScheme),
        _ => None,
    }
}
```

## Supported Signatures

- [Simple Signing](mechanism/simple/README.md)
- [Cosign](mechanism/cosign/README.md)