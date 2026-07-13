# Online SEV KBC module

This KBC extends the `offline_sev_kbc` to support requests made at runtime.
This KBC is designed to be used with [simple-kbs](https://github.com/confidential-containers/simple-kbs).
Since this KBC is an extension of the `offline_sev_kbc` it has many similar properties.
For instance, it only supports SEV(-ES) and requires an injected secret and the [EFI Secret](https://docs.kernel.org/security/secrets/coco.html) kernel module.
The injected secret should be a `connection` secret from the `simple-kbs` and should have the guid `1ee27366-0c87-43a6-af48-28543eaf7cb0`.
This injected connection contains a symmetric key that is used to encrypt and verify online requests made by the KBC.
Specifically, the connection is defined in the `Connection` struct as a `client_id` UUID and a `key` string. The key string should be a base64-encoded 256-bit key.
The injection secret is a JSON serialization of the `Connection` struct.
Today only `aes_gcm_256` is supported as the encryption scheme.
The connection is protected by the SEV(-ES) secret injection process, which provides confidentiality, integrity, and prevents replay.
`simple-kbs` generates a new symmetric key for every connection. The KBC requests each online secret with a randomized guid to prevent replay.

## Usage

This KBC expects a `KBS_URI` parameter. The KBC will not function without the EFI Secret module. The EFI Secret module is supported by the 5.19 or newer kernel.
The module should be available but not loaded before KBC is invoked. The KBC will not be able to unload the module if /proc has not been mounted.

To run:

```
make KBC=online_sev_kbc && make install
attestation-agent --keyprovider_sock 127.0.0.1:47777 --getresource_sock 127.0.0.1:48888
```

To regenerate protobuf file:
```
cargo build --features=online_sev_kbc,gen-proto
git add src/kbc_modules/online_sev_kbc/keybroker.rs
git commit
```
