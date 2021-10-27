# Offline file system KBC module

The offline file system KBC reads keys from a file present in the guest file system.
**The offline file system KBC is only secure to use when the guest file system is at no point readable by a hypothetical adversary**, such as with IBM Secure Execution for Linux (IBM Z & LinuxONE).
Being an offline module, it is not a broker _client_ in the stricter sense of the word.
See the [offline file system KBS](../../../sample_kbs/src/enc_mods/offline_fs_kbs/README.md) for correspondent software to wrap keys.

## Usage

The guest must provide OpenSSL at runtime.
Keys must be provided in the guest file system at `/etc/aa-offline_fs_kbc-keys.json` like:
```
{
    "key_id1": "cGFzc3BocmFzZXdoaWNobmVlZHN0b2JlMzJieXRlcyE=",
    ...
}
```

with the 32-byte keys base64-encoded.

AA with this KBC can be build and run with e.g.:
```
cd attestation-agent
make KBC=offline_fs_kbc && make install
attestation-agent --grpc_sock 127.0.0.1:50000
```
