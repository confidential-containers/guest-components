# Compatibility Matrix

This document tracks compatibility between guest-components and [Trustee](https://github.com/confidential-containers/trustee) (the server-side components including KBS, Attestation Service, and RVPS).

## KBS Protocol Version

Guest-components and Trustee communicate using the KBS (Key Broker Service) protocol. Both sides must use compatible protocol versions.

| Protocol Version | Status     | Notes                                      |
|------------------|------------|--------------------------------------------|
| v0.4.0           | Current    | Used in CoCo v0.15.0+                      |
| v0.3.0           | Deprecated | Legacy, not recommended                    |

## Release Compatibility

The following table shows tested version combinations. Versions are coordinated through [CoCo umbrella releases](https://github.com/confidential-containers/confidential-containers/tree/main/releases).

| CoCo Release | guest-components | Trustee  | KBS Protocol | Release Date |
|--------------|------------------|----------|--------------|--------------|
| v0.17.0      | v0.16.0          | v0.16.0  | v0.4.0       | Nov 2025     |
| v0.16.0      | v0.15.0          | v0.15.0  | v0.4.0       | Oct 2025     |
| v0.15.0      | v0.14.0          | v0.14.0  | v0.4.0       | Sep 2025     |
| v0.14.0      | v0.13.0          | v0.13.0  | v0.4.0       | May 2025     |
| v0.13.0      | v0.12.0          | v0.12.0  | v0.4.0       | Mar 2025     |

**Note:** Using mismatched versions may work but is not tested. For production deployments, use versions from the same CoCo release.

## TEE Platform Support

### Attestation Support Matrix

| TEE Platform       | guest-components | Trustee  | Architecture | Status       |
|--------------------|------------------|----------|--------------|--------------|
| Intel TDX          | v0.8.0+          | v0.8.0+  | x86_64       | Stable       |
| Intel SGX          | v0.7.0+          | v0.7.0+  | x86_64       | Stable       |
| AMD SEV-SNP        | v0.7.0+          | v0.7.0+  | x86_64       | Stable       |
| AMD SEV(-ES)       | v0.7.0+          | v0.7.0+  | x86_64       | Stable       |
| Azure TDX vTPM     | v0.9.0+          | v0.9.0+  | x86_64       | Stable       |
| Azure SNP vTPM     | v0.9.0+          | v0.9.0+  | x86_64       | Stable       |
| ARM CCA            | v0.10.0+         | v0.10.0+ | aarch64      | Experimental |
| IBM Secure Exec    | v0.10.0+         | v0.10.0+ | s390x        | Stable       |
| Hygon CSV          | v0.12.0+         | v0.12.0+ | x86_64       | Experimental |
| NVIDIA GPU         | v0.15.0+         | v0.15.0+ | x86_64       | Experimental |

### Feature Flags

guest-components uses feature flags to enable TEE-specific code. The following table maps TEE platforms to the required build configuration:

| TEE Platform       | `TEE_PLATFORM` | Attester Feature Flag |
|--------------------|----------------|-----------------------|
| Intel TDX          | `tdx`          | `tdx-attester`        |
| Intel SGX          | (manual)       | `sgx-attester`        |
| AMD SEV-SNP        | `snp`          | `snp-attester`        |
| AMD SEV(-ES) + SNP | `amd`          | `snp-attester`        |
| Azure TDX vTPM     | `az-tdx-vtpm`  | `az-tdx-vtpm-attester`|
| Azure SNP vTPM     | `az-snp-vtpm`  | `az-snp-vtpm-attester`|
| Azure CVM vTPM     | `az-cvm-vtpm`  | Both Azure attesters  |
| ARM CCA            | `cca`          | `cca-attester`        |
| IBM Secure Exec    | `se`           | `se-attester`         |

## Component Dependencies

Trustee embeds certain guest-components crates as dependencies:

| Trustee Component     | guest-components Crate | Purpose                          |
|-----------------------|------------------------|----------------------------------|
| KBS                   | `kbs_protocol`         | Protocol types and client        |
| Attestation Service   | `kms`                  | KMS provider implementations     |

These dependencies are pinned to specific git revisions in Trustee's `Cargo.toml`. When upgrading, ensure the pinned revision is compatible with your guest-components version.

## Breaking Changes

### v0.15.0+
- KBS configuration format updated
- Token validation changes

### v0.10.0+
- Added support for multiple concurrent attesters
- Changed attestation evidence format for some platforms

### v0.8.0+
- Initial stable KBS protocol v0.4.0

## Testing Compatibility

To verify compatibility between guest-components and Trustee:

1. **Unit Tests**: Run component tests independently
   ```shell
   # In guest-components
   cd attestation-agent/kbs_protocol
   cargo test
   ```

2. **Integration Tests**: Use the same CoCo release versions
   ```shell
   # Start Trustee KBS
   docker run -p 8080:8080 ghcr.io/confidential-containers/staged-images/kbs:v0.16.0

   # Test with guest-components client
   cd attestation-agent
   cargo test --features kbs
   ```

3. **End-to-End**: Deploy using CoCo operator with matched versions

## Reporting Compatibility Issues

If you encounter compatibility issues:

1. Verify you're using versions from the same CoCo release
2. Check the [KBS protocol version](#kbs-protocol-version) matches
3. Open an issue with:
   - guest-components version/commit
   - Trustee version/commit
   - TEE platform
   - Error messages

File issues at:
- guest-components: https://github.com/confidential-containers/guest-components/issues
- Trustee: https://github.com/confidential-containers/trustee/issues
