# IMPLEMENTATION

## Definition of terms

### CC

CNCF Confidential Containers, the parent project of Confidential Data Hub (CDH).

### KBS

Key Broker Service.

### KBC

Key Broker Client, the Client of KBS.

### KBS protocol

The protocol used by a class of KBS to communicate with its KBC, such as EAA, GOP, ISECL, etc.

### KBS instance

A specific instance of KBS class to comminicate with KBC instance during runtime.

### KBC module

A class of KBC implementation of the specific KBS protocol. In CDH, this is embodied as a plugin in
[`confidential-data-hub/kms/src/plugins/kbs`](../../confidential-data-hub/kms/src/plugins/kbs).

### KBC instance

The instantiated object of a KBC existing in CDH's runtime. It is used to actually handle UnWrapKey/get-resource requests.

## KeyProvider protocol

Under the CC framework, this is the protocol for communication between the ocicrypt caller and the key provider service (CDH). Since CDH exists as a keyprovider service from the perspective of ocicrypt, this protocol conforms to the format of the standard keyprovider protocol. In order to better support functions different from a standard keyprovider, we further standardize the DC parameters in the standard keyprovider protocol. Its contents and the meanings of its fields are as follows:

> [!NOTE]
> Historically this protocol was implemented directly by the `attestation-agent` binary. This
> functionality has since moved to `confidential-data-hub`, which still advertises itself under
> the legacy ocicrypt provider name `attestation-agent` for backward-compatible annotation
> handling (see [`ocicrypt_config.rs`](../../confidential-data-hub/hub/src/config/ocicrypt_config.rs)).

### UnWrapKey API Request

```
{
    "op":"keyunwrap",
    "keyunwrapparams":{
        "dc":{
            "Parameters":{
                "attestation-agent":[
                    "KBC_NAME::KBS_URI <base64encode>"
                ],
                "DecryptConfig":{"Parameters":{}}
            }
        }
    },
    "annotation": #layer-annotation,
}
```

The `dc` field in the `keyunwrappparams` field is "Decryption Configuration information", in which the `Parameters` field contains its main contents. The first item of `Parameters` is the name of the keyprovider service which ocicrypt called (here, it needs to be attestation-agent, for backward compatibility) and the user-defined parameter passed to the target service (Base64 encoded). We define the user-defined parameter as ` "KBC_NAME::KBS_URI" `. This standard format is used to transfer KBC selection information and corresponding KBS access information to CDH. For more questions here, please refer to the section 'Pass KBC name and KBS URI to CDH' below.

The `"annotation"` field is the main content passed to CDH. In fact, it is the layer annotation field of the container image to be decrypted. This field contains the payload to be decrypted by CDH. For more information about layer annotation, please refer to the following two chapters 'Encryption and decryption of container image' and 'Layer annotation'.

### UnWrapKey API Response

```
{
    "keyunwrapresults": {
        "optsdata": #decrypted-payload,
    }      
}
```

This is the response returned to ocicrypt, where the `"optsdata"` field contains the plain payload in the layer annotation decrypted by CDH.

### WrapKey API

CDH only provides the service of decryption path as a keyprovider, so the wrapkey API is not required. However, in order to maintain the consistency of keyprovider protocol, CDH provides an empty wrapkey API and will return "UNIMPLEMENT" in the ` "optsdata"` field of response.

## Encryption and decryption of container image

During image layer encryption, a request to keyprovider WrapKey() API is called by ocicrypt. A KBS instance may implement this API to encrypt the ‘Private Layer Block Cipher Options’ (PLBCO for short) with Key Encryption Key (KEK for short), and package the encrypted PLBCO and KBS specific parameters into the layer annotation. ( Note: How to cooperate with KBS for encryption is customizable, and WrapKey() API does not have to be implemented by KBS. )

When decrypting the container image layer, kata-agent (ocicrypt-rs) will request CDH's UnWrapKey API, pass KBC name, KBS URI and layer annotation to CDH, and expect CDH to return the decrypted PLBCO (including LEK).

## Layer annotation

The producer of layer annotation is a KBS instance, so the format of layer annotation is specific yo KBS protocol and implementation. (If KBS is not used for encryption, layer annotation should also be set to KBS protocol specific format)

The consumer of layer annotation is a KBC instance that implements the corresponding KBS protocol, because only it can parse the annotation format of KBS protocol specific.

For a worked example of the resulting manifest annotations, see
[Inspecting the image](../coco_keyprovider/README.md#inspecting-the-image).

## KBC runtime

CDH is compiled with one or more KBC plugins enabled via cargo features (e.g. `kbs` enables `cc_kbc`;
`offline_fs_kbc` is always built in). At runtime, CDH reads the configured (or `aa_kbc_params`-derived)
KBC name and instantiates the matching plugin once; that instance is then reused to handle all
subsequent UnWrapKey/get-resource requests for the lifetime of the CDH process. See
[`confidential-data-hub/kms/src/plugins/kbs/mod.rs`](../../confidential-data-hub/kms/src/plugins/kbs/mod.rs)
for the current dispatch implementation.

## Pass KBC name and KBS URI to CDH

In the current implementation, KBC name and KBS URI are passed by the implementer of key provider protocol, e.g, ocicrypt and ocicrypt-rs.

### Cannot pass through layer annotation currently

These two information should not be placed in the layer annotation as part of the container image. There are two main reasons: 

1. **Flexibility**: keeping KBC name and KBS URI out of the image means the same encrypted image can be deployed against different KBC/KBS configurations without being rebuilt.
2. **Security**: layer annotation is public plaintext data. Without additional encryption protection, an attacker can launch DoS attacks by using a KBS URI to prevent the tenant from starting any confidential container based on that KBS; without additional integrity protection, an attacker can tamper with the contents and induce potential security problems while decrypting the image layer.

> [!WARNING]
> Layer annotations should stay independent of any particular KBC. In the current CoCo guest stack, image pull and layer decryption are handled by CDH, which obtains KBC/KBS configuration from CDH config (or related guest parameters), not from the image layers.

### Passed by ocicrypt instead of kata-agent

In the implementation of CDH, the KBC name and KBS URI are passed through the keyprovider protocol of ocicrypt, rather than by Kata agent in the startup phase of CDH.

KBC name::KBS URI is passed by the user-defined field reserved in the keyprovider protocol. The request of UnWrapKey API should be as follows: 

```
{
    "op":"keyunwrap",
    "keyunwrapparams":{
        "dc":{
            "Parameters":{
                "attestation-agent":[
                    "KBC_NAME::KBS_URI <base64encode>"
                ],
                "DecryptConfig":{"Parameters":{}}
            }
        }
    },
    "annotation": #kbs-protocol-specific,
}
```

When CDH receives the first unwrapkey request after startup, it will select the correct KBC (compile time option) according to KBC name and instantiate it. In subsequent requests, if the KBC name is the same, CDH always uses the same KBC instance to handle the request.

Although you may think that it seems more direct to pass these parameters in the startup phase of CDH from kata-agent, the current scheme of passing them through keyprovider protocol can unify the parameter receiving interface of CDH and make its architecture more scalable. In addition, the impact of this scheme on performance can be ignored because instantiating a KBC is very simple.

## Others

### KBC decryption flow

The KBC module parses the annotation field passed by ocicrypt-rs, obtains the connection address
information of the key broker service (KBS) and the ID of the KEK, and then communicates with KBS
to actually decrypt the payload (Image encryption key) in the annotation field. `cc_kbc` implements
this behavior, using `attestation-agent` to obtain a bearer token before talking to KBS.
`offline_fs_kbc` implements a simplified version of this flow for testing: it performs no
attestation and no KBS communication, instead reading the KEK/resources directly from a local file.

### gRPC and ttRPC

Compared with gRPC, ttRPC has the advantage of lighter weight. CDH, as a memory resident service on the client side of the CoCo guest stack, can use lightweight ttRPC to save more resources. Both gRPC and ttRPC are supported and selectable at compile time via the `grpc`/`ttrpc` cargo features.
