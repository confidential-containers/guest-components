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

[confidential-data-hub](confidential-data-hub)
Confidential Data Hub.

[coco-keyprovider](attestation-agent/coco_keyprovider/)
CoCo Keyprovider. Used to encrypt the container images.

## Build

A `Makefile` is provided to quickly build Attestation Agent/Api Server Rest/Confidential Data Hub for a given platform.

```shell
make build TEE_PLATFORM=$(TEE_PLATFORM)
make install DESTDIR=/usr/local/bin
```

The `TEE_PLATFORM` parameter can be
- `none`: for tests with non-confidential guests
- `all`: for all following platforms
- `fs`: for platforms with encrypted root filesystems (i.e. s390x)
- `tdx`: for Intel TDX
- `az-tdx-vtpm`: for Intel TDX with Azure vTPM
- `sev`: for AMD SEV(-ES)
- `snp`: for AMD SEV-SNP
- `amd`: for both AMD SEV(-ES) and AMD SEV-SNP
- `az-snp-vtpm`: for AMD SEV-SNP with Azure vTPM
- `se`: for IBM Secure Execution (SE)

by default, `kbs`/`sev` as a resource provider will be built in Confidential Data Hub. If you do not want enable any
default except for only builtin `offline-fs-kbc`, you can build with `NO_RESOURCE_PROVIDER` flag set to `true`.

```shell
make build TEE_PLATFORM=$(TEE_PLATFORM) NO_RESOURCE_PROVIDER=true
```

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs?ref=badge_large)
