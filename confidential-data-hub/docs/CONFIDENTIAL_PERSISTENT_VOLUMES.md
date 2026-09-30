# Confidential Persistent Volumes

## Authors

- Noel Jackson ([@noeljackson](https://github.com/noeljackson)) <n@noeljackson.com>

## Summary

This proposal adds a small typed CDH API for persistent block storage in a confidential VM. A trusted service in the guest gives CDH a raw block device and a manifest reference. CDH retrieves the key after attestation, verifies the volume, and returns a decrypted block device. The trusted service mounts that device for the workload, so the application never receives the raw device, key, or mount privileges.

This design does not require a new CSI driver and does not prevent a future CoCo CSI proxy or DAV-aware driver. CDH begins after a raw block device reaches the trusted guest. The current `volumeDevices` path and future DirectVolume, Cloud API Adaptor, or CSI-proxy integrations can use the same `SecureVolumeService` contract while keeping the manifest contract, on-disk format, and existing encrypted volumes compatible.

The CDH contract is not specific to Kubernetes or Kata. Kata Agent can be the trusted guest service, but a Peer Pod or standalone confidential VM can use the same API if it has an equivalent trusted service to identify and authorize an attached device, mount the filesystem, and clean it up.

CDH does not provision or attach storage. A CSI driver, cloud provider, hypervisor, or other platform component must supply the raw block device to the confidential VM.

## First version

The first version supports one fixed read-write profile: LUKS2, journaled dm-integrity with HMAC-SHA256, and ext4. It can initialize a completely zero device or reopen a device that CDH previously initialized with the same volume identity, key, size, and LUKS UUID.

LUKS2 with dm-integrity is the first supported protection profile, not a requirement of the design. Other guest-side block-encryption formats can use the same flow when CDH implements them as reviewed typed profiles.

CDH does not need to know whether the platform provisioned the disk statically or dynamically. The CDH contract is neutral to that choice, while the first Kata integration validates only dynamically provisioned Block PVCs. Importing a pre-populated disk, static end-to-end integration, read-only access, shared writers, rollback protection, resize, snapshots, migration, and key rotation are not included in the first version.

## Relationship to `secure_mount`

CDH already has a generic `SecureMountService`. It accepts a storage type, free-form options, flags, and a mount point. It supports several storage plugins, lets the caller describe how to prepare the storage, and performs the mount itself.

This proposal recommends a separate `SecureVolumeService` for confidential persistent volumes.

| `SecureMountService` | `SecureVolumeService` |
| --- | --- |
| Generic storage and mount API | Narrow persistent-volume activation API |
| Caller supplies free-form storage options and a mount point | Caller supplies a device ID, manifest URI, and requested access |
| CDH mounts the storage | CDH returns a decrypted block device |
| Existing API remains available | Trusted guest service performs the final mount |

`SecureVolumeService` does not replace `secure_mount`. The two APIs can reuse the same internal block-device and encryption code, but the CoCo persistent-volume flow should use only the typed service. The downstream prototype also contains an experimental `secure_mount` option named `sourceType: persistent`; that was used to develop the LUKS lifecycle and is not proposed as a second CoCo interface. This API boundary should be reviewed with CDH maintainers before an upstream submission.

## CDH API

The proposed protobuf contract is:

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

message DeactivateVolumeResponse {}

service SecureVolumeService {
  rpc ActivateVolume(ActivateVolumeRequest) returns (ActivateVolumeResponse);
  rpc DeactivateVolume(DeactivateVolumeRequest) returns (DeactivateVolumeResponse);
}
```

`device_id` uses the guest kernel's `MAJ:MIN` form. `manifest_uri` names a content-addressed manifest in Trustee/KBS. `requested_access` is the access already authorized by the trusted guest service. The enum reserves read-only access for a future profile, but the first version accepts only `VOLUME_ACCESS_READ_WRITE`.

CDH returns an opaque `activation_id` for cleanup, the guest-only plaintext mapper path in `device_path`, and the access it actually enforced. It does not accept a mount point, container name, filesystem type, key URI, mapper name, or cryptographic option from the caller.

## Manifest

Before the VM uses the volume, a trusted storage administrator generates a random volume key and creates a manifest. The checked-in Codewire documentation fixture uses 32 public test bytes of `0x5a`; those bytes are not deployment key material. Its resource payload is the following 456 UTF-8 bytes, serialized with compact separators in the displayed member order and with no BOM or trailing newline:

```json
{"schemaVersion":3,"volumeId":"be31063a-8ec8-46d5-aa17-75cda1729370","volumeVersion":"be31063a-8ec8-46d5-aa17-75cda1729370-v3","deviceSizeBytes":21474836480,"access":"readWrite","protection":{"type":"luks2-integrity-rw","profileVersion":1,"keyUri":"kbs:///default/codewire-workspace-luks/be31063a-8ec8-46d5-aa17-75cda1729370","keySha256":"60bf07c488aad18fda339df07e4fbc47b4f00be71711936f18d04d352ad01890","luksUuid":"f617a73e-b03d-4b58-b1ae-354c72276ea0"}}
```

The SHA-256 of those exact bytes is `de7120550b6e85aea6e1e436158e595a61048d46e121870e46595e9fdad0d3ec`, so the exact manifest URI is:

```text
kbs:///default/codewire-storage-manifests/sha256-de7120550b6e85aea6e1e436158e595a61048d46e121870e46595e9fdad0d3ec
```

The fixture and a test that feeds it through current content-address, schema, profile, and key validation are checked in on the downstream implementation branch at [`codewire-cpv-manifest-v3.fixture.json`](https://github.com/noeljackson/guest-components/blob/downstream/confidential-storage/confidential-data-hub/hub/test_files/codewire-cpv-manifest-v3.fixture.json).

For production, the administrator stores a random 32-byte key and its matching manifest in Trustee/KBS and configures their release policy. The key is secret material and is not included in the manifest. CDH configuration must set a nonempty `protected_resource_uri_prefixes` list containing `default/codewire-workspace-luks`, and every persistent-volume manifest must place `keyUri` inside that protected namespace. This keeps the public resource API from retrieving the same key that internal activation is allowed to use.

CDH verifies the manifest URI digest, rejects unknown manifest fields, and checks the supported schema, stable volume ID, exact device size, requested access, fixed protection type and version, key URI, key digest, and canonical LUKS UUID. Content addressing proves which manifest CDH received; Trustee/KBS policy still decides whether the attested guest may receive that manifest and key.

`volumeVersion` is an administrator-visible generation identifier. CDH binds the volume ID, volume version, exact manifest digest, and protection profile version together for mapper and authenticated recovery identity. It is not a monotonic counter and does not provide freshness or rollback protection.

## Five-step flow

### Step 1: The platform attaches the raw block device

The platform attaches a raw block device to the confidential VM. The device is either completely zero for first use or contains a volume previously initialized by this CDH profile. CDH does not call CSI, a cloud API, or a hypervisor to create or attach it.

### Step 2: A trusted guest service authorizes the request

A trusted service inside the confidential VM matches the platform device to an approved workload declaration. It authorizes the device, manifest URI, access, and final workload destination before calling `ActivateVolume`. CDH intentionally does not decide which container or process should receive the mounted filesystem.

### Step 3: CDH verifies and activates the volume

CDH fetches the content-addressed manifest and its key through the attested Trustee/KBS resource path. It verifies the manifest, key, requested access, real block-device size, and LUKS identity before returning a mapper. A new device is initialized only after a complete zero scan. A known device is reopened only after its authenticated metadata and complete LUKS2 header pass verification. A failed reopen never becomes permission to format the disk.

### Step 4: The trusted guest service mounts the filesystem

CDH returns the activation ID and plaintext mapper path. The trusted guest service mounts the ext4 filesystem at a private guest path, applies the authorized ownership, and exposes it only to the intended workload. The application sees a normal directory and needs no storage sidecar or mount-capable entrypoint.

### Step 5: The trusted guest service cleans up

The trusted guest service removes the workload mount and unmounts ext4 before calling `DeactivateVolume`. CDH closes the mapper and forgets the activation. The platform can then detach the raw device.

## LUKS2 header and data integrity

The host controls the raw disk, including the bytes that hold the LUKS2 header. A normal LUKS checksum detects accidental corruption but does not make a host-provided header trustworthy. CDH therefore authenticates the complete header before `cryptsetup` may use it.

```text
Disk offset   Size       Contents
0x00000000    16 MiB     Standard detached LUKS2 header
0x01000000    4 KiB      Authenticated state record A
0x01001000    4 KiB      Authenticated state record B
0x01002000    remaining  Encrypted ext4 data and dm-integrity tags
```

The first 16 MiB is a standard detached LUKS2 header generated by `cryptsetup`. CoCo defines the two state records that follow it. Each record is exactly 4 KiB; multibyte integers are big-endian and every reserved byte must be zero.

| Bytes | Field |
| --- | --- |
| 0-7 | Magic: `COCOPV\0\0` |
| 8-9 | Metadata-format version: `2` |
| 10 | State: `1` prepared, `2` initializing, or `3` ready |
| 11 | Reserved |
| 12-19 | Sequence: `1`, `2`, or `3`, matching the state |
| 20-51 | SHA-256 of the volume ID |
| 52-83 | SHA-256 of the volume version |
| 84-115 | SHA-256 of the exact manifest bytes |
| 116-119 | Protection-profile version: `1` |
| 120-123 | Reserved |
| 124-155 | HMAC-SHA256 of the complete detached LUKS2 header; zero only in the prepared state |
| 156-187 | HMAC-SHA256 of the complete state record |
| 188-4095 | Reserved |

Here, `volumeKey` is the 32-byte key released by Trustee/KBS:

```text
binding   = SHA256(volumeId) || SHA256(volumeVersion) || manifestDigest || BE32(profileVersion)
authKey   = HMAC-SHA256(volumeKey, "coco-cdh-persistent-luks2-auth-key-v2" || binding)
headerMac = HMAC-SHA256(authKey, "coco-cdh-persistent-luks2-header-v2" || binding || completeHeader)
recordMac = HMAC-SHA256(authKey, "coco-cdh-persistent-luks2-record-v2" || recordWithRecordMacZeroed)
```

CDH checks both state records and uses the authentic record with the newest valid sequence. It then copies the complete header into a guest-only temporary file, verifies `headerMac`, and gives that same verified copy to `cryptsetup`.

### First initialization

CDH first confirms that the complete device is zero. It creates the LUKS2 header in guest-only temporary storage and asks `cryptsetup` to create the fixed read-write profile with journaled HMAC-SHA256 dm-integrity. The LUKS UUID comes from the manifest. CDH then stores the detached header and authenticated recovery state with the ciphertext disk.

The alternating state records let CDH recognize the last complete state after an interrupted initialization without treating an existing filesystem as a blank disk.

### Reopen

On reopen, CDH copies the complete header from the host-controlled disk into guest-only temporary storage and verifies its HMAC before use. It then checks the real device size and the manifest's LUKS UUID. Only after those checks pass does CDH give that same verified guest copy to `cryptsetup`.

This guest copy closes the gap between checking a host-controlled header and using it. A modified or foreign header is rejected before a mapper is created. The persistent header does not need to be stored in Trustee/KBS because the host cannot forge its HMAC without the volume key.

### Ciphertext integrity

Header authentication protects the encryption configuration. Journaled dm-integrity separately authenticates mutable ciphertext sectors and keeps data and authentication-tag writes crash-consistent. It detects ciphertext or tag forgery and corruption, but not replay of a previously valid ciphertext/tag pair to the same sector.

These checks do not provide freshness. The host can replay an older complete disk image containing an older but internally valid header, state, ciphertext, and integrity tags. Same-sector ciphertext/tag replay, selective rollback, and mixed filesystem epochs are explicitly accepted first-version risks. The host can also withhold the disk, substitute a new all-zero disk, or attempt another attachment; the first version does not claim availability, continuity, rollback protection, or distributed writer fencing.

Where rollback matters, the application must use application-level versioning or a trusted monotonic state service, with the expected state authenticated outside the hostile disk. Replay can cause ext4 to parse adversarial, replay-corrupted state even when each sector's HMAC is valid, so deployments must keep the guest kernel on a reviewed, patched baseline.

## Runtime integration

The CDH API is the same for each confidential-VM environment, but device attachment, policy, mounting, and cleanup belong to the runtime integration.

- **Kata Containers:** Kata Agent is the trusted guest service. The first version requires a raw Block PVC through CSI `volumeDevices` and `shared_fs=none`; otherwise a host-mounted shared-filesystem path could violate the plaintext boundary. Possible future DirectVolume integration, Agent policy, container bind mounts, and cleanup are described in the [downstream Kata proposal](https://github.com/noeljackson/kata-containers/blob/confidential-persistent-storage/docs/design/proposals/confidential-persistent-storage.md) and tracked in [kata-containers issue #13638](https://github.com/kata-containers/kata-containers/issues/13638).
- **Peer Pods:** The cloud provider must attach the disk to the PodVM. A trusted service in that PodVM must authorize the workload, translate the attached disk into a guest device ID, call CDH, and mount the returned mapper.
- **Standalone confidential VMs:** A cloud or hypervisor attaches the disk. A trusted guest daemon or boot service must provide the authorization and mount lifecycle that Kata Agent provides in Kata.

Calling CDH directly is not a complete workload authorization design. An integration without a trusted guest service must define how the request is approved and how the plaintext mount is confined to the intended workload.

## Acceptance

The first version must demonstrate:

- first initialization of a completely zero block device;
- reopen of the same encrypted ext4 volume after guest restart;
- attested retrieval and verification of a content-addressed manifest and key;
- rejection of a wrong key, size, access, profile, UUID, or nonzero unknown disk;
- rejection of a modified detached header before `cryptsetup` creates a mapper;
- detection of forged or corrupted ciphertext/tag pairs through dm-integrity, excluding replay of a previously valid pair;
- return of only the activation ID, guest mapper, and enforced access to the trusted caller; and
- cleanup that unmounts before deactivation and never exposes the key or raw device to the workload.

Loop-backed tests can verify the CDH contract independently of CSI or a particular confidential-VM runtime.

## Downstream prototype

The implementation work is available on the downstream [guest-components `downstream/confidential-storage` branch](https://github.com/noeljackson/guest-components/tree/downstream/confidential-storage). It adds the typed CDH API, attested manifest and key retrieval, persistent LUKS2 activation, authenticated header handling, crash recovery, dm-integrity, cleanup, and focused tests.

The Kata end-to-end design document is maintained separately on the downstream [`confidential-persistent-storage` design branch](https://github.com/noeljackson/kata-containers/blob/confidential-persistent-storage/docs/design/proposals/confidential-persistent-storage.md). Its implementation-validation branches are listed in that document. These downstream documents and branches are prototypes for discussion; they have not been submitted as upstream pull requests.

## Later work

Read-only-many needs a separate immutable profile with a trusted content identity such as a dm-verity root hash. Imported pre-populated volumes, distributed writer fencing, external freshness, resize, snapshots, migration, and key rotation each require separate designs.

## Integration FAQ

### Is CDH tied to CSI, DirectVolume, the Cloud API Adaptor, or Kata?

No. CDH starts after a raw block device exists inside the trusted guest. Kubernetes CSI with `volumeDevices`, DirectVolume, the Cloud API Adaptor for a Peer Pod, or platform-specific storage for a standalone confidential VM can all deliver that device. Those components attach and identify the disk; CDH verifies and activates it. A trusted guest service must still authorize the workload, mount the returned device, and clean it up.

### Do different device transports need different CDH APIs?

No. They should all end at the same `ActivateVolume(device_id, manifest_uri, requested_access)` call. CSI, DirectVolume, Cloud API Adaptor, and hypervisor details belong to the platform integration and its authorization policy, not to CDH.

### Can CDH trust DirectVolume `mountInfo`?

No. `mountInfo` is host-controlled transport metadata. An integration may use it to locate and attach a candidate disk, but it must not let it choose the manifest, key, protection profile, filesystem, access, ownership, or workload destination. Those values must be fixed by the CDH profile or authorized by a measured workload declaration.

### Is a CoCo-specific CSI driver required?

No. CDH needs a raw block device inside the trusted guest, not a particular CSI driver. Bare-metal Kata can use an unchanged block-capable CSI driver through `volumeDevices`. Peer Pods still need the Cloud API Adaptor or another platform component to attach the disk to the PodVM, but both paths can use the same CDH API.

### How do static and read-only volumes fit?

Static versus dynamic provisioning does not change the CDH API. Static provisioning requires a trusted process to prepare or import the disk and publish its matching manifest and key. Read-only-many additionally requires an immutable content identity that every guest verifies. Static integration and a future read-only profile can reuse the same activation API.
