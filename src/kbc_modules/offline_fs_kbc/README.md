# Offline file system KBC module

The offline file system KBC reads keys from a file present in the guest file system.
**The offline file system KBC is only secure to use when the guest file system is at no point readable by a hypothetical adversary**, such as with IBM Secure Execution for Linux (IBM Z & LinuxONE).
Being an offline module, it is not a broker _client_ in the stricter sense of the word.

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

The KBC can be run with e.g.:
```
cargo run --release --no-default-features --features offline_fs_kbc -- --grpc_sock 127.0.0.1:50000
```
