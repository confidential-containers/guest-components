# IMPLEMENTATION

## Definition of terms

### KBS

Key Broker Service.

### KBC

Key Broker Client, the Client of KBS.

### KBS protocol

The protocol used by a class of KBS to communicate with its KBC, such as EAA, GOP, ISECL, etc.

### KBS instance

A specific instance of KBS class to comminicate with KBC instance during runtime.

### KBC module

A class of KBC implementation of the specific KBS protocol. In the code implementation, it is embodied as the mod.rs in a KBC source.

### KBC instance

The instantiated object of KBC existing in AA runtime. It is used to actually handle UnWrapKey requests. 

## KeyProvider protocol

Under Kata CC framework, the protocol for communication between AA caller (ocicrypt) and AA. Since AA exists as a keyprovider service from the perspective of ocicrypt, this protocol conforms to the format of the standard keyprovider protocol. In order to better support the special functions of AA different from keyprovider, we further standardize the DC parameters in the standard keyprovider protocol and set the unique standard format of AA, Its contents and the meanings of its fields are as follows:

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

The `dc` field in the `keyunwrappparams` field is "Decryption Configuration information", in which the `Parameters` field contains its main contents. The first item of `Parameters` is the name of the keyprovider service which ocicrypt called (here, it needs to be attestation-agent) and the user-defined parameter passed to the target service (Base64 encoded). We define the user-defined parameter as ` "KBC_NAME::KBS_URI" `This standard format is used to transfer KBC selection information and corresponding KBS access information to AA. For more questions here, please refer to the section 'Pass KBC name and KBS URI to AA' below.

The `"annotation"` field is the main content passed to AA. In fact, it is the layer annotation field of the container image to be decrypted. This field contains the payload to be decrypted by AA. For more information about layer annotation, please refer to the following two chapters 'Encryption and decryption of container image' and 'Layer annotation'.

### UnWrapKey API Response

```
{
    "keyunwrapresults": {
        "optsdata": #decrypted-payload,
    }      
}
```

This is the response returned to ocicrypt, where the `"optsdata"` field contains the plain payload in the layer annotation decrypted by AA.

### WrapKey API

AA only provides the service of decryption path as a keyprovider, so the wrapkey API is not required. However, in order to maintain the consistency of keyprovider protocol, AA provides an empty wrapkey API and will return "UNIMPLEMENT" in the ` "optsdata"` field of response.

## Encryption and decryption of container image

During image layer encryption, a request to keyprovider WrapKey() API is called by ocicrypt. A KBS instance may implement this API to encrypt the ‘Private Layer Block Cipher Options’ (PLBCO for short) with Key Encryption Key (KEK for short), and package the encrypted PLBCO and KBS specific parameters into the layer annotation. ( Note: How to cooperate with KBS for encryption is customizable, and WrapKey() API does not have to be implemented by KBS. )

When decrypting the container image layer, kata-agent (ocicrypt-rs) will request AA's UnWrapKey API, pass KBC name, KBS URI and layer annotation to AA, and expect AA to return the decrypted PLBCO (including LEK).

## Layer annotation

The producer of layer annotation is a KBS instance, so the format of layer annotation is specific yo KBS protocol and implementation. (If KBS is not used for encryption, layer annotation should also be set to KBS protocol specific format)

The consumer of layer annotation is a KBC instance that implements the corresponding KBS protocol, because only it can parse the annotation format of KBS protocol specific.

## KBC runtime

During the compilation of AA, it is optional to specify the KBC module(s) to compile through the conditional compilation option. AA will compile the mod.rs of these KBCs you specify, and register these KBC modules and the functions that instantiate them in AA's built-in 'KBC module list'.

KBC RUNTIME is a subsystem in AA which is used to instantiate KBC, manage KBC instances and encapsulate KBC instance interfaces. At runtime of AA, KBC runtime will dynamically select the corresponding KBC module from the KBC module list according to the KBC name in the UnWrapKey request, create a KBC instance and register it in the map of the current running instance. The KBC standard encapsulation interface provided by KBC runtime is then invoked to handle the request.

For the current design scenario of kata CC, only one KBC instance of AA on a k8s pod exists in the whole life cycle of the pod. This KBC instance will be created when AA receives the first UnWrapKey request. However, the implementation of KBC runtime provides good scalability for multiple KBC instances that may occur in other practice scenarios or in the future of kata CC.

## Pass KBC name and KBS URI to AA

In the current implementation, KBC name and KBS URI are passed by the implementer of key provider protocol, e.g, ocicrypt and ocicrypt-rs.

### Cannot pass through layer annotation currently

These two information should not be placed in the layer annotation as part of the container image. There are two main reasons: 

1. **Flexibility**: not binding KBC name and KBS URI to container image can improve the cross platform portability of container image. (for example, suppose a KBC can only support the SEV platform. If the KBC name or KBS URI is written to the layer annotation when encrypting a container image, it means that the encrypted container image can only run on the SEV platform).
2. **Security**: layer annotation is public plaintext data. Without additional encryption protection, an attacker can launch DoS attacks by using KBS URI to prevent the tenant from starting any confidential container based on the KBS; Without additional integrity protection, an attacker can tamper with the contents and induce potential security problems in the process of decrypting the image layer.

**! ! ATTENTION ! ! : **However, it must be noted here that for the first reason mentioned above, we do not rule out the possibility that there may be KBCs supporting various platforms (EAA protocol KBC is trying to do so). In this case, placing KBC name in layer annotation will not affect the cross platform portability of container image, but will support the complex scenarios such as "different layers of a same container image use different KBS protocol to encrypt" more flexibly. Therefore, the current AA code implementation retains the scalability of multiple KBC instances at runtime in order to better support the above possible changes in the future.

### Passed by ocicrypt instead of kata-agent

In the implementation of AA, the KBC name and KBS URI are passed through the keyprovider protocol of ocicrypt, rather than by Kata agent in the startup phase of AA.

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

When AA receives the first unwrapkey request after startup, it will select the correct KBC from KBC module list (compile time option) according to KBC name and instantiate it. In subsequent requests, if the KBC name is the same, AA always uses the same KBC instance to handle the request.

Although you may think that it seems more direct to pass these parameters in the startup phase of AA from kata-agent, the current scheme of passing them through keyprovider protocol can unify the parameter receiving interface of AA and make the architecture of AA more scalable. In addition, the impact of this scheme on performance can be ignored because instantiating KBC is very simple.

## Others

### Sample KBC

At the current stage, the sample KBC module uses hard coded KEK for decryption. In the formal scenario, the KBC module needs to parse the annotation field passed by ocicrypt-rs, obtain the connection address information of the key broker service (KBS) and the ID of the KEK, and then communicate with KBS to actually decrypt the payload (Image encryption key) in the annotation field.

### gRPC and ttRPC

Compared with gRPC, ttRPC has the advantage of lighter weight. AA, as a memory resident service on the client side of kata cc V0 architecture, using lightweight ttRPC will save more resources. At present, grpc is used for end-to-end testing. Wait until ocicrypt-rs supports ttrpc, AA can cooperate with the modification. Later, AA can make the use of grpc/ttrpc configurable at compile time. This needs to be discussed with the developers of ocicrypt rs.