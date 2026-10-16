# cc-op Crate — Design Document

## Overview

The `cc-op` crate is the guest-side cryptographic library for Confidential Container Operations.
It provides the HPKE payload decryption, stream key derivation, and stream encryption/decryption
logic used by the `kata-agent` when the `cc-op` feature is enabled.

The crate is consumed by the `kata-agent-cc-op` wrapper crate, which re-exports its public API
conditionally on the `cc-op` Cargo feature flag. The high-level design rationale and threat model
are documented in the kata-agent cc-op design document.

---

## Crate Structure

```
cc-op/
├── src/
│   ├── lib.rs              # Public API, global state, payload dispatch
│   ├── main.rs             # CLI test harness (development only)
│   ├── hpke/
│   │   ├── mod.rs          # Re-exports decrypt module
│   │   └── decrypt.rs      # HPKE auth-decrypt + channel key derivation
│   └── processors/
│       ├── mod.rs          # StreamProcessor trait
│       ├── aesgcm.rs       # AES-256-GCM framed processor (non-TTY exec)
│       ├── aesgcmtty.rs    # AES-256-GCM framed processor (TTY exec) — with reassembly buffer
│       └── null.rs         # Pass-through processor (disabled / testing)
```

---

## Global State

`lib.rs` holds three process-wide singletons using `std::sync::OnceLock`:

| Static | Type | Set by | Purpose |
|---|---|---|---|
| `VERIFYING_KEY` | `ecdsa::VerifyingKey` | `init_ccop` (reads `ccop.toml` from initdata) | Authenticates the workload owner's HPKE sender identity |
| `RECEIVER_PRIVATE_KEY` | `P256SecretKey` | `set_agent_private_key` (called from the agent after CDH provisioning) | HPKE receiver key; used to decrypt the exec payload |
| `RANDOM_BYTES` | `Vec<u8>` | `set_random_bytes` (called from the agent after CDH provisioning; ≥ 32 bytes) | Input keying material (HKDF-SHA-256 IKM) for the attach/logs stream keys |

`is_ccop_set()` returns `true` when `VERIFYING_KEY` is present. cc-op protection is active for
any `ExecProcess` request once this condition holds, even if `RECEIVER_PRIVATE_KEY` has not yet
been set — the payload decryption path (`get_exec_crypto`) checks both and returns an error if
either is absent.

---

## Initialization Flow

```
kata-agent boot
  │
  ├─ read initdata / ccop.toml
  │    └─ init_ccop(path)
  │         └─ set_auth_public_key(pem_cert)
  │              └─ parse X.509 cert → extract P-256 SubjectPublicKeyInfo
  │                   → store in VERIFYING_KEY (OnceLock)
  │
  └─ CreateContainer (sandbox container)
       ├─ get_cdh_resource("kbs+secretprov:///credentials?...&secret_type=p256")
       │    │   (CDH → AA → Trustee remote attestation)
       │    └─ set_agent_private_key(pem_str)
       │         └─ parse PKCS#8 or SEC1 PEM → store in RECEIVER_PRIVATE_KEY (OnceLock)
       │
       └─ get_cdh_resource("kbs+secretprov:///credentials?...&secret_name=ccop_random&secret_type=random")
            └─ set_random_bytes(bytes)
                 └─ require ≥ 32 bytes → store in RANDOM_BYTES (OnceLock)
```

All three `OnceLock` values are write-once. A second call to any setter returns an error,
preventing accidental re-initialization.

---

## Exec Payload Processing — `verify_ccop_args`

When the agent receives an `ExecProcess` RPC that carries a `--payload <base64>` argument:

1. `parse_args` extracts the base64 string from the argument list.
2. `get_exec_crypto` dispatches on the payload type field (currently only type `"C"` is supported).
3. For type `"C"`:
   - The raw bytes are deserialized from MessagePack into a `Payload` struct containing the
     encapsulated key, ciphertext, and AAD fields (version, namespace, pod name, container name,
     timestamp).
   - `encode_aad` serializes the AAD fields into a deterministic byte string.
   - `hpke_auth_decrypt_with_context` decrypts the payload using HPKE Auth mode
     (KEM: P-256 / HKDF-SHA-256, KDF: HKDF-SHA-256, AEAD: AES-128-GCM).
   - The HPKE opener context is retained and passed to `derive_channel_keys_from_opener`.
4. The returned `CryptoRunData::ExecMode` carries the decrypted argument list and two 32-byte
   session keys (`in_key`, `out_key`). No IVs are needed: both `AesGcmProcessor` (non-TTY) and
   `AesGcmTtyProcessor` (TTY) generate per-frame nonces internally.

### Payload wire format (type `"C"`, MessagePack)

| Field | Type | Description |
|---|---|---|
| `type` | `String` | `"C"` — authenticated+encrypted exec payload |
| `version` | `u8` | Protocol version (AAD) |
| `namespace` | `String` | Kubernetes namespace (AAD) |
| `podname` | `String` | Pod name (AAD) |
| `containername` | `String` | Container name (AAD) |
| `timestamp` | `u64` | Unix timestamp in seconds (AAD — replay defence, not yet enforced) |
| `encapsulatedkey` | `Vec<u8>` | HPKE encapsulated sender key (65 bytes, uncompressed P-256 point) |
| `ciphertext` | `Vec<u8>` | HPKE-encrypted and authenticated command arguments |

---

## HPKE Module — `hpke/decrypt.rs`

### Algorithm Suite

| Parameter | Value |
|---|---|
| KEM | `DhP256HkdfSha256` |
| KDF | `HkdfSha256` |
| AEAD | `AesGcm128` |
| Mode | `Auth` (sender public key is cryptographically bound to the ciphertext) |
| Info string | `b"ccop->agent command v1"` |

### `hpke_auth_decrypt_with_context`

Sets up an HPKE Auth receiver context using the agent's P-256 private key and the workload
owner's P-256 public key (extracted from `VERIFYING_KEY`). Decrypts and authenticates the
ciphertext in a single call, then returns both the plaintext and the live `AeadCtxR` opener.

### `derive_channel_keys_from_opener`

Exports two 32-byte secrets from the HPKE exporter interface using
fixed label strings. The receiver deliberately swaps the `encrypt`/`decrypt` labels relative
to the sender so that both sides derive a matching asymmetric key pair for the session:

| Export label | Assigned to receiver field | Used for |
|---|---|---|
| `"channel-decrypt-key"` | `encrypt_key` | Encrypting outbound data (stdout/stderr) |
| `"channel-encrypt-key"` | `decrypt_key` | Decrypting inbound data (stdin) |

No IV or nonce material is exported here. Both `AesGcmProcessor` (non-TTY) and
`AesGcmTtyProcessor` (TTY) generate per-frame nonces internally (8 random bytes || 4-byte
big-endian sequence counter), so a session-level IV is not required.

### AAD Encoding — `encode_aad`

The AAD byte string is assembled in a deterministic big-endian format:

```
[ version:1B ]
[ namespace_len:2B ][ namespace:N ]
[ podname_len:2B   ][ podname:N   ]
[ container_len:2B ][ container:N ]
[ timestamp:8B     ]
```

---

## Stream Processors

After the HPKE payload is decrypted, the agent installs a `StreamProcessor` on the exec session.
All processors implement the same two-method trait:

```rust
pub trait StreamProcessor: Send + Sync + std::fmt::Debug {
    fn process_input(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn process_output(&mut self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}
```

`process_input` handles data arriving from the client (stdin — decrypt).
`process_output` handles data leaving the guest toward the client (stdout/stderr — encrypt).

### `AesGcmProcessor` (non-TTY exec, `aesgcm.rs`)

Used for non-TTY exec sessions. Both directions use AES-256-GCM with independent keys and a
monotonically increasing 32-bit counter embedded in the 12-byte nonce. The counter occupies the
last four bytes of the nonce; the first eight bytes carry random material for each output frame.
The framing follows the same approach as `AesGcmTtyProcessor`: an 8-byte header carrying the
frame length and sequence number is authenticated as AAD.

**Input (decrypt) frame format:**
```
[ header:8B ][ nonce:12B ][ ciphertext+auth_tag ]

  header = [ length:4B BE ][ seq:4B BE ]
  nonce  = [ random:8B    ][ seq:4B BE ]
```

`length` covers `nonce + ciphertext + auth_tag` (i.e. everything after the header).

**Output (encrypt) frame format:**
```
[ MAGIC:4B 0xD1A2E3B4 ][ header:8B ][ nonce:12B ][ ciphertext+auth_tag ]

  header = [ length:4B BE ][ seq:4B BE ]
  nonce  = [ random:8B    ][ seq:4B BE ]
```

The output frame is the input frame prefixed by the magic value, which allows the cc-op client
to distinguish cc-op frames from unencrypted output. The magic is not part of the AAD; the
8-byte header is.

The header is fed as AAD, so tampering with the length or sequence number is detected by the
authentication tag. On input, the sequence number in the header must match the one embedded in
the nonce, and must be strictly greater than the last accepted value — frames with a
sequence ≤ the last accepted one are rejected before decryption, providing replay and reordering
protection within a session. A single `process_input` call may carry several concatenated
frames; unlike `AesGcmTtyProcessor`, no reassembly buffer is kept, so a frame split across
calls is rejected as incomplete.

### `AesGcmTtyProcessor` (TTY exec, `aesgcmtty.rs`)

Used for TTY exec sessions (`ccop exec -it`), where stdin, stdout, and stderr are multiplexed
over a single PTY channel. Provides both confidentiality and integrity via AES-256-GCM with
per-record framing. Both directions use the same frame layout:

```
[ header:8B ][ nonce:12B ][ ciphertext+auth_tag ]

  header = [ length:4B BE ][ seq:4B BE ]
  nonce  = [ random:8B    ][ seq:4B BE ]
```

The header is fed as AAD so tampering with the length or sequence number is detected by the
authentication tag. Both sides enforce strict monotonic ordering of `seq` to prevent replay
and reordering attacks.

Unlike `AesGcmProcessor`, this processor maintains an internal `input_buf: Vec<u8>` reassembly
buffer. The TTY transport is a PTY master (`StreamType::TermMaster`), not a pipe. The PTY
line-discipline may deliver a single frame split across multiple `WriteStreamRequest` RPCs
(for example, a 45-byte frame arriving as 20 bytes then 25 bytes). The buffer accumulates
bytes across calls and drains complete verified frames; partial trailing bytes are held for
the next call.

### `NullProcessor` (`null.rs`)

Pass-through: both directions return the input data unchanged. Used when cc-op is not active
or in test scenarios.

---

## `CryptoRunData` Enum

The return value of `verify_ccop_args` (exec path) and `get_init_crypto` (attach/logs path):

```rust
pub enum CryptoRunData {
    AttachLogsMode {
        enabled: bool,
        has_sandbox_id: bool,
        in_key: Vec<u8>,     // 32B — derived from RANDOM_BYTES
        out_key: Vec<u8>,    // 32B — derived from RANDOM_BYTES
    },
    ExecMode {
        args: Vec<String>,   // decrypted command-line arguments
        enabled: bool,
        in_key: Vec<u8>,     // 32B — decrypt stdin (AesGcmProcessor / AesGcmTtyProcessor)
        out_key: Vec<u8>,    // 32B — encrypt stdout/stderr
        // No IVs: both AesGcmProcessor and AesGcmTtyProcessor generate per-frame nonces
        // internally (random(8B) || seq(4B BE)); a session-level IV is not required.
    },
}
```

`get_init_crypto` derives the `AttachLogsMode` keys from `RANDOM_BYTES` (provisioned by Trustee
via the CDH) using HKDF-SHA-256 with no salt, `RANDOM_BYTES` as the input keying material, and
distinct `info` labels:

| Key | HKDF info label | Length |
|---|---|---|
| `in_key` | `b"ccop attach logs in_key v1"` | 32 B |
| `out_key` | `b"ccop attach logs out_key v1"` | 32 B |

It returns an error if `RANDOM_BYTES` has not been set.

---

## Known Limitations and Future Work

| Area | Status |
|---|---|
| Attach/logs support | Provide Stream Processors to protect `attach` and `logs`. |
| Timestamp enforcement (replay protection) | AAD contains a `timestamp` field, but the agent does not yet enforce a freshness window. |
| Key rotation | Neither the agent receiver key nor the user auth key can be rotated without restarting the VM. |
