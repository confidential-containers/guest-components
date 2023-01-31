# CC-KBC Encryption module

This encryption module corresponds to the [CC KBC](../../../../src/kbc_modules/cc_kbc).
It wraps keys to be used by that KBC.
As this is done ahead of time rather than at the runtime of the KBC, it is not a broker _service_ in the stricter sense of the word.

## Usage

Generate a random encryption key first:

```shell
head -c32 < /dev/random > test_key_1
```

Then register this key to [KBS](https://github.com/confidential-containers/kbs) resource repository,
The resource path (`<repository>/<type>/<tag>`) of this key in KBS will be used as part of the key ID when encrypting the container image in the next step.

The sample keyprovider with CC-KBC encryption module can be run with e.g.:
```
cargo run --release --features cc_kbc_enc -- --keyprovider_sock 127.0.0.1:50000
```

### Encrypt Container Image

To correspond with the sample keyprovider as described above, an `ocicrypt.conf` like
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
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --encryption-key provider:attestation-agent:$(realpath test_key_1):<key_id> oci:busybox oci:busybox_encrypted
```

The `<key_id>` parameter format should be:
```
cc_kbc://<kbs-address>/<repository>/<type>/<tag>
```

Where:
- `<kbs-address>`: e.g: `127.0.0.1:8080`, `example.kbs.com` etc.
- `<repository>/<type>/<tag>`: As mentioned above, this is the resource path of the encryption key in KBS.

For example:
```
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf skopeo copy --encryption-key provider:attestation-agent:$(realpath test_key_1):cc_kbc://127.0.0.1:8080/my_repo/test/test_key_1 oci:busybox oci:busybox_encrypted
```
