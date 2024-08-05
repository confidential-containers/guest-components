# Attester Plugins

This crate provides attester plugins for different platforms. An [attester](https://www.rfc-editor.org/rfc/rfc9334.html#section-7.2) plugin can provide the following abilities

- Get remote attestation evidence.
- Extend runtime measurement.
- Check the initdata binding.

## Evidence Getter Tool

This crate provides a simple tool to detect the current platform type and get related quote due to given report data.

Build the binary with the default features or with a specific TEE attester support (e.g., `tdx-attester`)
```shell
git clone https://github.com/confidential-containers/guest-components.git
cd guest-components/attestation-agent/attester

cargo build --features=bin --bin evidence_getter --release

cargo build --no-default-features --features bin,tdx-attester --bin evidence_getter --release
```

Get evidence
```shell
echo $EVIDENCE_STRING | ../../target/release/evidence_getter 
```

Here, `$EVIDENCE_STRING` is a string/bytes of up to 64 bytes.
