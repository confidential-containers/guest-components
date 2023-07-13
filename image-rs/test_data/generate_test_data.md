## Generate keypair and container image for unit and integration tests

### Create PEM private key
```shell
$ openssl genrsa -out private_key_for_tests.pem
```

### Create PEM public key from PEM private key
```shell
$ openssl rsa -inform pem -outform pem -pubout -in private_key_for_tests.pem -out public_key_for_tests.pem
```

### Create gzip compressed container image
```shell
$ skopeo copy  --dest-compress-format gzip docker://busybox:latest docker://user/busybox_gzip
```

### Create zstd compressed container image
```shell
$ skopeo copy  --dest-compress-format zstd docker://busybox:latest docker://user/busybox_zstd
```

### Create JWE encrypted container image
```shell
$ skopeo copy --encryption-key jwe:public_key_for_tests.pem docker://busybox:latest docker://user/busybox_encrypted
```

### Create CoCo-Keyprovider encrypted container image
Follow the [README](https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/coco_keyprovider/README.md)
