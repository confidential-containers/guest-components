# Offline file system KBS module

This KBS corresponds to the [offline file system KBC](../../../../src/kbc_modules/offline_fs_kbc/README.md).
It wraps keys to be used by that KBC.
As this is done ahead of time rather than at the runtime of the KBC, it is not a broker _service_ in the stricter sense of the word.

## Usage

Keys must be provided in a file (e.g. `aa-offline_fs_kbc-keys.json`) like:
```
{
    "key_id1": "cGFzc3BocmFzZXdoaWNobmVlZHN0b2JlMzJieXRlcyE=",
    ...
}
```

with the 32-byte keys base64-encoded.
This file must be available to the KBC later (see documentation linked above).

You can also use the included `generate_keys.sh` to generate some sample keys based on `/dev/random` if this fits your use case sufficiently well.

The KBS can be run with e.g.:
```
cargo run --release --features offline_fs_kbs -- --grpc_sock 127.0.0.1:50000
```

### Running skopeo

To correspond with the KBS as described above, an `ocicrypt.conf` like
```json
{
    "key-providers": {
        "attestation-agent": {
            "grpc": "127.0.0.1:50000"
        }
    }
}
```

is required.
To encrypt e.g. `oci:busybox` with the key file path and key ID suggested above, run
```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --encryption-key provider:attestation-agent:$(realpath aa-offline_fs_kbc-keys.json):key_id1 oci:busybox oci:busybox_encrypted
```
