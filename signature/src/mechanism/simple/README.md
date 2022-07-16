# Simple Signing

Simple Signing is the first signature that CC supports. Refer to 
[CCv1 Image Security Design](../../../../docs/ccv1_image_security_design.md#image-signing).

## Policy Format

Simple Signing is verified due to the container's policy configuration file.

A Policy Requirement of Simple Signing should be like this

```json
{
    "type": "signedBy",
    "scheme": "simple",
    "keyType": "<KEY-TYPE>",
    "keyData": "<PUBKEY-DATA-IN-BASE64>",
    "keyPath": "<PATH-TO-THE-PUBKEY>",
    "signedIdentity": <JSON-OBJECT>,
},
```

Here, 
* The `type` field must be `signedBy`, showing that this Policy Requirement
needs a signature verification.
* The `scheme` field must be `simple`, showing this signature is Simple Signing.
* The `keyType` field indicates the pubkey's type. Now only `GPGKeys` is supported.
* The `keyData` field includes the pubkey's content in base64.
* The `keyPath` field indicates the pubkey's path. 
* `signedIdentity` includes a JSON object, refer to [signedIdentity](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md#signedby) for detail.

**WARNING**: Must specify either `keyData` or `keyPath`, and must not both.
