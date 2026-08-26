# Confidential persistent volumes

## Status

Proposal for a typed CDH lifecycle for persistent encrypted block volumes.

## Problem

CDH can create and open encrypted block storage through `secure_mount`, but
that API accepts a free-form option map and a mount point. It works as storage
plumbing, but it is not a good authorization boundary for persistent volumes:
an untrusted caller can choose the key reference, protection settings,
filesystem options, and mount behavior.

A confidential workload also needs to reopen the same encrypted filesystem in
a new guest without exposing its key or plaintext to the host. Reopen failure
must never be treated as permission to format an existing device.

## Proposed contract

The first version supports one read-write guest per volume. A CSI driver or
other host adapter provides an unmounted ciphertext block device, a versioned
manifest URI, and requested access. The host does not provide a key URI,
cryptographic profile, filesystem, or formatting options.

The guest-side flow is:

1. kata-agent authorizes the manifest URI, requested access, container, and
   mount destination using measured policy.
2. CDH fetches the versioned manifest through its existing attested resource
   path, then fetches the key named by that manifest.
3. CDH initializes an all-zero device or authenticates and reopens a known
   device. It returns a constrained mapper path and the effective access.
4. kata-agent verifies the returned access, mounts fixed ext4, and exposes the
   filesystem to the authorized container.
5. On last use, kata-agent unmounts ext4, deactivates the CDH activation, and
   releases the device in reverse order.

The new API is intentionally separate from `secure_mount`:

```protobuf
enum VolumeAccess {
    VOLUME_ACCESS_UNSPECIFIED = 0;
    VOLUME_ACCESS_READ_ONLY = 1;
    VOLUME_ACCESS_READ_WRITE = 2;
}

message ActivateVolumeRequest {
    string device_id = 1;
    string manifest_uri = 2;
    VolumeAccess requested_access = 3;
}

message ActivateVolumeResponse {
    string activation_id = 1;
    string device_path = 2;
    VolumeAccess effective_access = 3;
}

message DeactivateVolumeRequest {
    string activation_id = 1;
}
```

`activation_id` is opaque. Deactivation is idempotent. CDH rejects unknown
manifest versions, mutable aliases, access escalation, caller-supplied storage
options, and attempts to use an activation with a different device.

## Manifest

The manifest is a versioned, write-once Trustee resource. Trustee
administration is part of the trusted control plane because it already owns
reference values, resource policy, and key release.

The final resource tag must equal `volumeVersion`. This gives measured policy
an exact versioned URI and rejects aliases such as `latest` before key release.

An initial read-write manifest is:

```json
{
  "schemaVersion": 1,
  "volumeId": "tenant/workload/volume-1",
  "volumeVersion": "volume-1-v1",
  "deviceSizeBytes": 1073741824,
  "access": "readWrite",
  "protection": {
    "type": "luks2-integrity-rw",
    "keyUri": "kbs:///tenant/storage-keys/volume-1-v1",
    "luksUuid": "be31063a-8ec8-46d5-aa17-75cda1729370"
  }
}
```

The profile fixes the exact block-device size, LUKS2, journaled HMAC-SHA256
dm-integrity, and ext4. A size mismatch is rejected before mutation. New
profiles use a new identifier; the meaning of an existing profile never
changes. A deployment that cannot enforce write-once manifest resources can
add a digest-binding extension later.

## Persistent read-write profile

[guest-components #1648](https://github.com/confidential-containers/guest-components/pull/1648)
provides the crash-safe persistent LUKS mechanism. It scans a new device before
initialization, authenticates the detached LUKS header and state records, and
fails closed when an existing device cannot be reopened.

[guest-components #1663](https://github.com/confidential-containers/guest-components/pull/1663)
adds journaled dm-integrity and rejects unsupported options. Those mechanisms
remain internal to the profile rather than becoming fields in the activation
request.

CDH owns zero-only initialization, authenticated recovery, LUKS2,
dm-integrity, and first-use ext4 formatting. It returns the mapper but does not
mount it for the workload. The caller owns the final fixed ext4 mount and
sandbox-scoped reference counting.

## Security properties and limits

The design provides:

- guest-only key retrieval and plaintext access;
- measured authorization before activation;
- authenticated LUKS metadata and crash state;
- detection of modified ciphertext through dm-integrity; and
- fail-closed handling of unknown, damaged, or substituted initialized media.

The host still controls availability and can replay a complete older valid
snapshot, substitute another all-zero device, or attach one device to two
authorized guests. `ReadWriteOncePod` reduces accidental concurrent writers,
but it is not hostile-host fencing. This version does not claim rollback
protection or storage continuity.

Read-write-many, resize, migration, online snapshots, key rotation, arbitrary
filesystems, arbitrary mount options, and immutable read-only-many are outside
the first version.

## Compatibility and testing

The typed lifecycle is additive. Existing `secure_mount` consumers keep their
current behavior, but Kata persistent volumes use only the typed API. There is
no fallback from the typed request to free-form options.

Required tests cover manifest parsing, access negotiation, duplicate
activation, idempotent deactivation, zero-only initialization, interrupted
initialization, reopen in a new guest, wrong key, altered metadata or payload,
substituted devices, unsupported manifests, resize rejection without
mutation, and ordered cleanup. A composed test should use a loop-backed block
device so the contract is independent of any CSI vendor.
