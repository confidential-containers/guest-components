# Confidential Container Tools and Components 
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs?ref=badge_shield)

This repository includes tools and components for confidential container images.

## Components

[Attestation Agent](attestation-agent)
An agent for facilitating attestation protocols.
Can be built as a library to run in a process-based enclave or built as a process that runs inside a confidential vm.

[image-rs](image-rs)
Rust implementation of the container image management library.

[ocicrypt-rs](ocicrypt-rs)
Rust implementation of the OCI image encryption library.

[api-server-rest](api-server-rest)
CoCo Restful API server.

[coco-keyprovider](attestation-agent/coco_keyprovider/)
CoCo Keyprovider. Used to encrypt the container images.

## Build

A `Makefile` is provided to quickly build Attestation Agent/Api Server Rest/Confidential Data Hub of a given platform.

```shell
make build TEE_PLATFORM=$(TEE_PLATFORM)
make install DESTDIR=/usr/local/bin
```

The `TEE_PLATFORM` parameter can be
- `test`: for test
- `tdx`: for Intel TDX
- `sev`: for AMD SEV

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs?ref=badge_large)
