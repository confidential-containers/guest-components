# README

Sample KBS is a very simple KBS skeleton, which currently has the following functions:

1. It can be used to encrypt the container image to test the KBC module in AA. Sample KBS provides a modular encryption mechanism. Different encryption modules can be used according to different kbcs to be tested.

Sample KBS can be a reference code base for you to quickly build your own KBS.

## Test KBC modules

### Encryption

Build and run sample KBS. You must explicitly specify the encryption module to use through the --features parameter (sample_enc for example): 

```
cd attestation-agent/sample_kbs
RUST_LOG=sample_kbs cargo run --features sample_enc --release -- --grpc_sock 127.0.0.1:50000
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

Encrypt the container image. You can pass in the special parameters required by the encryption module through the command line parameters of skopeo (here, the string "test" is taken as an exemplary special parameter): 

```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --insecure-policy --encryption-key provider:attestation-agent:test oci:busybox oci:busybox-encrypted
```

After encryption, it can be seen that busybox-encrypted is generated in the current directory.

### Decryption

Build and run AA: 

```
cd attestation-agent
make KBC=sample_kbc && make install
RUST_LOG=attestation_agent attestation-agent --grpc_sock 127.0.0.1:48888
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

Decrypt container image: 

```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --insecure-policy --decryption-key provider:attestation-agent:sample_kbc::null oci:busybox-encrypted oci:busybox-decrypted
```

