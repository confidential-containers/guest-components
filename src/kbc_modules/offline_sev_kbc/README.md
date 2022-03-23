# Offline SEV KBC module

This KBC does not communicate with a KBS at runtime, but rather retrieves keys that were injected at boot. This KBC is designed for use with SEV or SEV-ES secret injection and the EFI Secret kernel module, which coordinates with OVMF to expose injected secrets to guest userspace. If you would like to use an offline KBC without secret injection, consider the offline\_fs\_kbc.

## Secret Injection

To use this KBC in conjunction with EFI Secret, you must carefully craft an injected secret. The secret should be a GUIDed secret table.

### Structure of the EFI secret area

```
  Offset   Length
  (bytes)  (bytes)  Usage
  -------  -------  -----
        0       16  Secret table header GUID (must be 1e74f542-71dd-4d66-963e-ef4287ff173b)
       16        4  Length of bytes of the entire secret area

       20       16  First secret entry's GUID
       36        4  First secret entry's length in bytes (= 16 + 4 + x)
       40        x  First secret entry's data

     40+x       16  Second secret entry's GUID
     56+x        4  Second secret entry's length in bytes (= 16 + 4 + y)
     60+x        y  Second secret entry's data
```

The secret table should include an entry with the GUID `e6f5a162-d67f-4750-a67c-5d065f2a9910`. The contents of this secret should be a JSON file in the following format where each key is 32-bytes and base64 encoded.

```
{
    "key_id1": "cGFzc3BocmFzZXdoaWNobmVlZHN0b2JlMzJieXRlcyE=",
    ...
}
```

## Usage

This KBC has no adjustable parameters. The KBC will not function without the EFI Secret module. The module should be available but not loaded before KBC is invoked. The KBC will not be able to unload the module if /proc has not been mounted.

To run:

```
make KBS=offline_sev_kbc && make install
attestation-agent --keyprovider_sock 127.0.0.1:47777 --getresource_sock 127.0.0.1:48888
```
