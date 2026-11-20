# Confidential Container Tools and Components
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs?ref=badge_shield)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/confidential-containers/guest-components/badge)](https://scorecard.dev/viewer/?uri=github.com/confidential-containers/guest-components)

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
CoCo RESTful API server.

[confidential-data-hub](confidential-data-hub)
Confidential Data Hub.

[coco-keyprovider](attestation-agent/coco_keyprovider/)
CoCo Keyprovider. Used to encrypt the container images.

## Tools

[secret-cli](confidential-data-hub/docs/SEALED_SECRET.md)
Utility for sealing and unsealing sealed secrets

[CDH Client](confidential-data-hub/README.md#client-tool)
A tool for exercising CDH endpoints

[CDH (One Shot)](confidential-data-hub)
One Shot version of CDH

[CoCo Keyprovider](attestation-agent/coco_keyprovider)
Keyprovider endpoint for encrypting images

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
- `snp`/`amd`: for AMD SEV-SNP
- `az-snp-vtpm`: for AMD SEV-SNP with Azure vTPM
- `se`: for IBM Secure Execution (SE)

By default, the `kbs` feature (`cc_kbc` / CoCo KBS) is enabled in Confidential
Data Hub. `offline_fs_kbc` is always built. To build without `cc_kbc`, set
`ENABLE_KBS=false`:

```shell
make build TEE_PLATFORM=$(TEE_PLATFORM) ENABLE_KBS=false
```

### Optional build parameters

The ttRPC and gRPC protos can be updated via run
```shell
make build-protos
```

## Compatibility

For compatibility information between guest-components and [Trustee](https://github.com/confidential-containers/trustee) (KBS, Attestation Service), see the [Compatibility Matrix](COMPATIBILITY.md).

This includes:
- Release version mappings
- TEE platform support status
- KBS protocol versions
- Breaking changes

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Fimage-rs?ref=badge_large)
