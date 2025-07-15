# Secure mount with Block Device

This guide helps an user to use confidential data hub to secure mount inside TEE environment.

## Preliminaries

- Ensure that [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/) is installed.

## Example

### Create a loop device

```shell
$ device_file="/tmp/test.img"
$ sudo dd if=/dev/zero of=$device_file bs=1M count=1000
$ sudo losetup -fP $device_file
$ device=$(sudo losetup -j $device_file | awk -F'[: ]' '{print $1}')
$ echo $device
# Output should be something like /dev/loop0
$ device_num=$(sudo lsblk -no MAJ:MIN $device)
$ echo $device_num
# Output should be something like 7:0
```

### Secure mount inside a TEE environment

1. Build the CDH and its client tool

Follow the instructions in the [CDH README](../../README.md#confidential-data-hub) and [Client Tool README](../../README.md#client-tool) to build the CDH and its client tool.

2. Install `libcryptsetup-dev`

```bash
sudo apt install -y libcryptsetup-dev
```

3. Run CDH
```shell
$ confidential-data-hub
```

4. Prepare a request JSON `storage.json`
```json
{
    "volume_type": "block-device",
    "options": {
        "deviceId": "7:5",
        "sourceType": "empty",
        "targetType": "fileSystem",
        "encryptionType": "luks2",
        "dataIntegrity": "true",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/test-path"
}
```

- Fields:
    - `volume_type`: The secure mount plugin type name. It determines how the rest of the fields are used.
    - `options`: A key-value map specifying the settings for the mount operation. Different plugins can define different keys in the options. In this example, all keys are for block devices.
    - `flags`: A string list specifying settings for the mount operation. Different plugins can define different uses for this field.
    - `mount_point`: The target mount path for the operation.

- Options Fields:
    - `deviceId`: **Optional**. The device number, formatted as "MAJ:MIN". At least one of `deviceId` or `devicePath` must be set. If both are set, `deviceId` will be used.
    - `devicePath`: **Optional**. The path of the source device path. At least one of `deviceId` or `devicePath` must be set. If both are set, `deviceId` will be used.
    - `sourceType`: **Required**. The type of the source device. Can be `"empty"` (for new/unencrypted devices) or `"encrypted"` (for existing encrypted devices).
    - `targetType`: **Required**. The type of the target mount point. Can be `"device"` (expose as a device file) or `"fileSystem"` (mount as a filesystem directory). See [Target Types](#target-types) for more details.
    - `encryptionType`: **Required**. The encryption type. Currently, only `luks2` is supported. Different encryption types require different parameters. See [Encryption Types](#encryption-types) for more details.
    - `key`: **Optional**. The key to encrypt or decrypt the device. If not set and `sourceType` is `"empty"`, a random 4096-byte key will be generated. Legal values start with:
        - `"sealed."`: Get the encryption key from the sealed secret.
        - `"kbs://"`: Get the encryption key from the KBS.
        - `"file://"`: Get the encryption key from the local file.


5. Make a request to CDH
For instance, using the ttrpc version of the client tool, call:
```shell
$ ttrpc-cdh-tool secure-mount --storage-path storage.json

# Check the target path to see if the mount succeeded
$ lsblk
# There will be an line with output like:
└─70c76258-8907-46ca-ac3b-cbfe1d18aeef 253:0    0   112M  0 crypt /mnt/test-path
```

### Source Types

`sourceType` field specifies the type of the source device:

- `"empty"`: The source device is empty or unencrypted. The device will be encrypted (wiped and formatted with LUKS2) before use.
- `"encrypted"`: The source device is already encrypted. The device will be decrypted and opened.

### Target Types

`targetType` field specifies the type of the target mount point:

- `"device"`: Expose the cleartext device via a symlink at the mount point pointing to `/dev/mapper/<name>`. This is useful when you want to access the device directly.
- `"fileSystem"`: Mount the cleartext device as a filesystem directory. This requires additional parameters:
    - `filesystemType`: **Required** when `targetType` is `"fileSystem"`. The filesystem type to mount. Currently supported: `ext4`.
    - `mkfsOpts`: **Optional**. Extra options passed verbatim to `mkfs.<fs>` when creating a new filesystem (only used when `sourceType` is `"empty"`).

### Operation Combinations

The combination of `sourceType` and `targetType` determines the operation:

- `sourceType: "empty"` + `targetType: "device"`: Encrypt the device and expose the cleartext device via symlink.
- `sourceType: "empty"` + `targetType: "fileSystem"`: Encrypt the device, create a filesystem, and mount it.
- `sourceType: "encrypted"` + `targetType: "device"`: Decrypt the device and expose the cleartext device via symlink.
- `sourceType: "encrypted"` + `targetType: "fileSystem"`: Decrypt the device and mount the existing filesystem.

Now we support the following filesystems:
- `ext4`

### Encryption Types

Block device supports different ways of encryption.

- `luks2`: LUKS2 encryption. More parameters are needed:
    - `dataIntegrity`: **Optional**. Enables dm-integrity to protect data integrity. Note that enabling data integrity will reduce IO performance by more than 30%. Accepted values are `"true"` or `"false"` (as strings). Default is `false`.
    - `mapperName`: **Optional**. Optional name for `/dev/mapper/<mapperName>`. If not set, the mapper name will be a randomly generated UUID.

### Best Practices

#### Ephemeral Storage

Ephemeral storage is a storage that is not persistent.

1. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and mount the plaintext device to `/mnt/dev-path` as a device file.

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/some-device",
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
        "devicePath": "/dev/some-device",
        "sourceType": "empty",
        "targetType": "fileSystem",
        "encryptionType": "luks2",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/directory-path"
}
```

#### Persistent Storage

1. Mount a `luks2` encrypted block device file and return the plaintext device path, mounting the plaintext to `/mnt/dev-path` as a device file. The decryption key is obtained from KBS.

We can prepare an encrypted block device file before mounting it. Using `"passphrase"` as passphrase to encrypt the block device file with luks2.

```bash
device_file="/tmp/test.img"
storage_key_path="/tmp/encryption_key"

sudo dd if=/dev/zero of=$device_file bs=1M count=1000
echo "passphrase" > "$storage_key_path"

cryptsetup --batch-mode luksFormat --type luks2 "$device_file" --sector-size 4096 \
	--cipher aes-xts-plain64 "$storage_key_path"
```

Then use the json payload

```json
{
    "volume_type": "block-device",
    "options": {
        "devicePath": "/dev/some-device",
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
device_file="/tmp/test.img"
storage_key_path="/tmp/encryption_key"
opened_device_name="test-name"
mount_dir="/mnt/luks2ext4-cdh-test"

sudo dd if=/dev/zero of=$device_file bs=1M count=1000
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
        "devicePath": "/tmp/test.img",
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