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
echo $EVIDENCE_STRING | ../../target/release/evidence_getter stdio
```

Here, `$EVIDENCE_STRING` is a string/bytes of up to 64 bytes.

## Adding TPM quote to evidence

Setup a TPM emulator by running the following commands:

```sh
sudo modprobe tpm_vtpm_proxy
mkdir -p /tmp/tpmdir
s​​wtpm_setup --tpm2 \
            --tpmstate /tmp/tpmdir \
            --createek --decryption \
            --create-ek-cert \
            --create-platform-cert \
            --pcr-banks - \
            --display

swtpm chardev --tpm2 \
              --tpmstate dir=/tmp/tpmdir \
              --vtpm-proxy \
              --daemon \
              --log file=/tmp/tpmdir/tpm.log,level=20 \
              --flags not-need-init
```

This will create a tpm device for example `/dev/tpm0`

If you want to read and extend sample PCRs for test you can use the following commands:

```sh
# Read all PCRs
tpm2_pcrread -T device:/dev/tpm0

# Read PCR an empty PCR (eg 11)
tpm2_pcrread sha256:11 -T device:/dev/tpm0

# Extend PCR
tpm2_pcrextend 11:sha256=6ea40aa7267bb71251c1de1c3605a3df759b86b22fa9f62aa298d4197cd88a3
```

For retrieving TPM quote, run the following:

```sh
../../target/release/evidence_getter commandline 12345678
```