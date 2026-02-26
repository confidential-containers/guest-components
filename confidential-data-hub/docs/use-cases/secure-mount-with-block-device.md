# Secure mount with Block Device

This guide helps an user to use confidential data hub to secure mount inside TEE environment.

## Preliminaries

- Ensure that `libcryptsetup-dev` is installed for **LUKS2** mode.
- Ensure that `zfsutils-linux` is installed and the ZFS kernel module is enabled for **ZFS** mode.

The block-device plugin supports two secure mount modes: **LUKS2** (`encryptionType: "luks2"`) and **ZFS** (`encryptionType: "zfs"`). The following [Configuration](#configuration) section summarizes common and mode-specific options; then [Best practices](#best-practices) covers loop-device preparation plus end-to-end flows for LUKS2 and ZFS.

## Configuration

CDH’s `secure_mount` API expects a JSON payload similar to the examples in this document, with the following top-level structure:

```json
{
  "volume_type": "block-device",
  "options": {
    "...": "..."
  },
  "flags": [],
  "mount_point": "/mnt/your-path"
}
```

### Common options

Common fields used by **both** LUKS2 and ZFS modes:

| Name              | Location     | Type / Values                                      | Required | Description |
| ----------------- | ----------- | -------------------------------------------------- | -------- | ----------- |
| `volume_type`     | top-level   | `"block-device"`                                  | Yes      | Selects the block-device plugin. Must be `"block-device"` for this guide. |
| `options.devicePath`      | `options`   | String path (e.g. `/dev/loop0`)                   | One of `devicePath` or `deviceId` | Path to the backing block device. If both `devicePath` and `deviceId` are set, `deviceId` wins. |
| `options.deviceId`        | `options`   | String `"MAJ:MIN"` (e.g. `"7:0"`)                 | One of `devicePath` or `deviceId` | Kernel major/minor device ID. CDH resolves it to a device path internally. |
| `options.sourceType`      | `options`   | `"empty"` \| `"encrypted"`                        | Yes      | `"empty"` means the device will be initialized and encrypted; `"encrypted"` means the device is already encrypted and should be opened. |
| `options.encryptionType`  | `options`   | `"luks2"` \| `"zfs"`                              | Yes      | Selects the encryption mode. LUKS2 uses dm-crypt; ZFS uses ZFS native encryption. |
| `options.key`             | `options`   | URI: `sealed.*`, `kbs://…`, or `file://…`         | No       | Where to fetch the encryption key. If omitted, CDH generates a random key (ephemeral storage). |
| `mount_point`     | top-level   | String path (e.g. `/mnt/my-path`)                 | Yes      | Path inside the guest where the cleartext device or filesystem becomes visible. |

### LUKS2-specific options

In addition to the common fields above, LUKS2 mode understands the following options:

| Name               | Type / Values                                | Required | Best-practice usage |
| ------------------ | -------------------------------------------- | -------- | ------------------- |
| `options.targetType`       | `"device"` \| `"fileSystem"`                 | Yes      | Use `"device"` when you want a cleartext block device (e.g. for a database that manages its own filesystem), and `"fileSystem"` when you want CDH to mount a filesystem for you. |
| `options.filesystemType`   | `"ext4"` (default) and other fs types        | Required when `targetType` is `"fileSystem"` | Set to `"ext4"` for most workloads. Must match the existing filesystem when `sourceType` is `"encrypted"`. In this case, ensure that `mkfs.ext4` is installed. |
| `options.mkfsOpts`         | String of extra args to `mkfs.<fs>`          | No       | Use only when `sourceType` is `"empty"` and you need to tune filesystem creation (e.g. `"-E lazy_journal_init=1"`). Leave empty for sane defaults. |
| `options.dataIntegrity`    | Boolean (`true` / `false`)                   | No (default `false`) | Enable (`true`) to turn on dm-integrity for stronger integrity guarantees; expect >30% IO performance overhead. Keep `false` for performance‑sensitive ephemeral storage. |
| `options.mapperName`       | String (e.g. `"my-mapped-device"`)           | No       | Set when you need a stable `/dev/mapper/<name>` for monitoring or debugging. When omitted, CDH generates a UUID-based name. |

### ZFS-specific options

In addition to the common fields above, ZFS mode understands the following options:

| Name              | Type / Values                     | Required | Best-practice usage |
| ----------------- | --------------------------------- | -------- | ------------------- |
| `options.pool`            | String (e.g. `"pool1"`)           | No (default `"zpool"`) | Choose a meaningful pool name per device or cluster (e.g. `"pool-ml-models"`). Reuse the same name when re‑importing an existing device. |
| `options.dataset`         | String (e.g. `"dataset1"`)        | No (default `"zdataset"`) | Name the dataset according to the workload (e.g. `"models"`, `"snapshots"`). Must match the existing dataset name when `sourceType` is `"encrypted"`. |

Notes and best practices:

- ZFS **always** mounts an encrypted dataset as a filesystem at `mount_point`; the current implementation ignores `targetType`, but you should still set it to `"fileSystem"` for clarity.
- For a **first-time mount** on a fresh device, use `sourceType: "empty"` with a strong `key` and explicit `pool` / `dataset` names; CDH will create the pool and encrypted dataset for you.
- For a **re-mount** on an already-encrypted device, use `sourceType: "encrypted"` with the same `pool`, `dataset`, and `key`; CDH will import the pool, load the key, and mount the dataset.

---

## Best practices

### Create a loop device

Prepare a block device (e.g. a file-backed loop device) that will be used for both LUKS2 and ZFS examples below.

```bash
device_file="/tmp/test.img"
sudo dd if=/dev/zero of=$device_file bs=1M count=1000
sudo losetup -fP $device_file
device=$(sudo losetup -j $device_file | awk -F'[: ]' '{print $1}')
echo $device
# Output should be something like /dev/loop0
device_num=$(sudo lsblk -no MAJ:MIN $device)
echo $device_num
# Output should be something like 7:0
```

Use `$device` (e.g. `/dev/loop0`) or `$device_num` (e.g. `7:0`) in the request JSON as `devicePath` or `deviceId` in the following sections.

---

### LUKS2 best practices

Commands, steps, and expected behavior when using **LUKS2** secure mount (`encryptionType: "luks2"`).

### Prerequisites

- Build CDH and the client tool: see [CDH README](../../README.md#confidential-data-hub) and [Client Tool README](../../README.md#client-tool).
- Install libcryptsetup and development library:

```bash
sudo apt install -y libcryptsetup-dev
```

### Step 1: Start CDH

```shell
$ confidential-data-hub
```

Leave it running (or run in background). Use another terminal for the following steps.

### Cases

Choose one of the follow cases.

#### Case 1: Ephemeral Storage with LUKS2

Ephemeral storage is a storage that is not persistent.

1. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and mount the plaintext device to `/mnt/dev-path` as a device file.

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "empty",
        "targetType": "device",
        "encryptionType": "luks2"
    },
    "flags": [],
    "mount_point": "/mnt/dev-path"
}
```

2. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and format the plaintext device file as an `ext4` file system, mounting the plaintext to `/mnt/directory-path` as a directory.

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "empty",
        "targetType": "fileSystem",
        "encryptionType": "luks2",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/directory-path"
}
```

#### Case 2: Persistent Storage with LUKS2

1. Mount a `luks2` encrypted block device file and return the plaintext device path, mounting the plaintext to `/mnt/dev-path` as a device file. The decryption key can either be obtained from KBS, or from local filesystem.

We can prepare an encrypted block device file before mounting it. Using `"passphrase"` as passphrase to encrypt the block device file with luks2.

```bash
storage_key_path="/tmp/encryption_key"
echo "passphrase" > "$storage_key_path"

cryptsetup --batch-mode luksFormat --type luks2 "$device_file" --sector-size 4096 \
	--cipher aes-xts-plain64 "$storage_key_path"
```

Then use the json payload

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "encrypted",
        "targetType": "device",
        "encryptionType": "luks2",
        "key": "file:///tmp/encryption_key"
    },
    "flags": [],
    "mount_point": "/mnt/dev-path"
}
```

2. Mount a `luks2` encrypted block device file, decrypt it and mount it as an `ext4` file system, mounting the plaintext to `/mnt/directory-path` as a directory. The `luks2` decryption key is obtained from KBS

We can prepare an encrypted block device file before mounting it. Using `"passphrase"` as passphrase to encrypt the block device file with `luks2`.

```bash
storage_key_path="/tmp/encryption_key"
opened_device_name="test-name"
mount_dir="/mnt/luks2ext4-cdh-test"

echo "passphrase" > "$storage_key_path"

cryptsetup --batch-mode luksFormat --type luks2 "$device_file" --sector-size 4096 \
	--cipher aes-xts-plain64 "$storage_key_path"

cryptsetup luksOpen -d "$storage_key_path" "$device_file" "$opened_device_name"
mkfs.ext4 "/dev/mapper/$opened_device_name"
mkdir -p "${mount_dir}"
mount "/dev/mapper/$opened_device_name" "${mount_dir}"
echo "some-data" > "${mount_dir}/confidential-data-file"

sync

umount "${mount_dir}"
cryptsetup luksClose "$opened_device_name"
```

Then you can use the following `secure_mount` request to mount the encrypted block device to a target path.

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "encrypted",
        "targetType": "fileSystem",
        "encryptionType": "luks2",
        "key": "file:///tmp/encryption_key",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/luks2ext4-cdh-test"
}
```

And you can read the plaintext file.
```shell
$ cat /mnt/luks2ext4-cdh-test/confidential-data-file
some-data
```

---

### ZFS best practices

Commands, steps, and expected behavior when using **ZFS** secure mount (`encryptionType: "zfs"`).

### Prerequisites

- Install ZFS userland and ensure the ZFS kernel module is loaded:

```bash
sudo apt install -y zfsutils-linux
# If needed, load the module:
sudo modprobe zfs
```

- Build CDH and the client tool (same as LUKS2). Start CDH (e.g. `confidential-data-hub`) before calling secure-mount.

### Step 1: Prepare encryption key file

ZFS mode requires a key (e.g. passphrase file) for the encrypted dataset.

```bash
zfs_key_path="/tmp/zfs_encryption_key"
echo "your-passphrase" > "$zfs_key_path"
```

Use this path in the request as `"key": "file:///tmp/zfs_encryption_key"`.

### Step 2: First-time mount (empty device → create zpool + encrypted dataset)

**Command:** Create mount point and request JSON. Replace `devicePath` with your block device (e.g. `$device` from “Create a loop device”).

Save as `storage-zfs.json`:

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "empty",
        "targetType": "fileSystem",
        "encryptionType": "zfs",
        "key": "file:///tmp/zfs_encryption_key",
        "pool": "pool1",
        "dataset": "dataset1"
    },
    "flags": [],
    "mount_point": "/mnt/zfs-dataset"
}
```

```shell
$ ttrpc-cdh-tool secure-mount --storage-path storage-zfs.json
```

**Expected phenomenon:**

- Command exits successfully.
- A new zpool and encrypted dataset exist; the dataset is mounted at the given path:

```shell
$ zpool list
NAME    SIZE  ALLOC   FREE  CKPOINT  EXPANDSZ   FRAG    CAP  DEDUP    HEALTH  ALTROOT
pool1   960M   266K   960M        -         -     0%     0%  1.00x    ONLINE  -

$ zfs list
NAME             USED  AVAIL  REFER  MOUNTPOINT
pool1            266K   832M    24K  /pool1
pool1/dataset1    98K   832M    98K  /mnt/zfs-dataset

$ mount | grep zfs
pool1 on /pool1 type zfs (rw,relatime,xattr,noacl,casesensitive)
pool1/dataset1 on /mnt/zfs-dataset type zfs (rw,relatime,xattr,noacl,casesensitive)
```

- You can read and write files under the mount point:

```shell
$ echo "secret" > /mnt/zfs-dataset/confidential.txt
$ cat /mnt/zfs-dataset/confidential.txt
secret
```

### Step 3: Unmount and re-mount (encrypted dataset, same key)

After unmounting (e.g. via `zpool export pool1`), the zpool is exported. To use the same device again, import and mount with `sourceType: "encrypted"`.

**Command:** Use the same `pool` and `dataset` names and key. Save as `storage-zfs-encrypted.json`:

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/loop0",
        "sourceType": "encrypted",
        "targetType": "fileSystem",
        "encryptionType": "zfs",
        "key": "file:///tmp/zfs_encryption_key",
        "pool": "pool1",
        "dataset": "dataset1"
    },
    "flags": [],
    "mount_point": "/mnt/zfs-dataset"
}
```

```shell
$ ttrpc-cdh-tool secure-mount --storage-path storage-zfs-encrypted.json
```

**Expected phenomenon:**

- Zpool is imported and the dataset is mounted at `/mnt/zfs-dataset`.
- Previously written data is still present:

```shell
$ cat /mnt/zfs-dataset/confidential.txt
secret
```

- `zpool list` and `zfs list` again show `pool1` and `pool1/dataset1` with mount point `/mnt/zfs-dataset`.

> [!INFO]
> - For ZFS, CDH always creates a filesystem-style mount.
> - `pool` and `dataset` must match what was used when the device was first formatted (`sourceType: "empty"`); otherwise import or mount may fail.
> - After unmount, the device can be moved to another machine; use the same `pool`, `dataset`, and key to re-mount there.

