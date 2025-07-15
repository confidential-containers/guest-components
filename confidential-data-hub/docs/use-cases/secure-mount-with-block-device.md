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
    "volume_type": "BlockDevice",
    "options": {
        "deviceId": "7:0",
        "action": "encryptFormatMount",
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
    - `deviceId`: The device number, formatted as "MAJ:MIN". At least one of `device_id` or `device_path` must be set. If both are set, `device_id` will be used.
    - `devicePath`: The path of the source device path. At least one of `device_id` or `device_path` must be set. If both are set, `device_id` will be used.
    - `action`: **Required** High-level action the blockdevice module performs. Different actions requires different parameters. See [Actions](#actions) for more details.
    - `encryptionType`: **Required**. The encryption type. Currently, only `luks2` is supported. Different encryption types require different parameters. See [Encryption Types](#encryption-types) for more details.


5. Make a request to CDH
```shell
$ client-tool secure-mount --storage-path storage.json

# Check the target path to see if the mount succeeded
$ lsblk |grep "encrypted_disk"
# Expected output:
└─encrypted_disk_OEyEj_dif 253:1    0 968.6M  0 crypt
  └─encrypted_disk_OEyEj   253:2    0 968.6M  0 crypt /mnt/test-path
```

### Actions

`action` field is used to specify the action to be performed on the block device. Now we support four different actions:

- `decryptMap`: Open an existing encrypted container and expose the cleartext device via `/dev/mapper/<name>`. More parameters are needed:
    - `decryptionKey`: **Required** Decryption key of the block device.
- `encryptMap`: Wipe the device, encrypted it, and expose the cleartext mapper. More parameters are needed:
    - `encryptionKey`: **Optional** Encryption key of the block device. If not set, generate a random 4096-byte key.
- `decryptMount`: Open an existing LUKS2 volume, map **and** mount an existing file-system. More parameters are needed:
    - `decryptionKey`: **Required** Decryption key of the block device.
    - `filesystemType`: **Required** Filesystem type.
- `encryptFormatMount`: Wipe the device, encrypt it, create a fresh file system, and mount it. More parameters are needed:
    - `encryptionKey`: **Optional** Encryption key of the block device. If not set, generate a random 4096-byte key.
    - `filesystemType`: **Required** Filesystem type.
    - `mkfsOpts`: **Optional** Extra options passed verbatim to `mkfs.<fs>`.

All the key related fields can starts with:
- `sealed.`: Get the encryption key from the sealed secret.
- `kbs://`: Get the encryption key from the KBS.
- `file://`: Get the encryption key from the local file.

Now we support the following filesystems:
- `ext4`

### Encryption Types

Block device supports different ways of encryption.

- `luks2`: LUKS2 encryption. More parameters are needed:
    - `dataIntegrity`: **Optional**. Enables dm-integrity to protect data integrity. Note that enabling data integrity will reduce IO performance by more than 30%. Accepted values are `true` or `false`. Default is `false`.
    - `mapperName`: **Optional**. Optional name for `/dev/mapper/<mapperName>`. If not set, the mapper name will be a random name.

### Best Practices

#### Ephemeral Storage

Ephemeral storage is a storage that is not persistent.

1. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and mount the plaintext device to `/mnt/dev-path` as a file.

```json
{
    "volume_type": "BlockDevice",
    "options": {
        "devicePath": "/dev/some-device",
        "action": "encryptMap",
        "encryptionType": "luks2"
    },
    "flags": [],
    "mount_point": "/mnt/dev-path"
}
```

2. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and format the plaintext device file as an `ext4` file system, mounting the plaintext to `/mnt/directory-path` as a directory.

```json
{
    "volume_type": "BlockDevice",
    "options": {
        "devicePath": "/dev/some-device",
        "action": "encryptFormatMount",
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
    "volume_type": "BlockDevice",
    "options": {
        "devicePath": "/dev/some-device",
        "action": "decryptMap",
        "encryptionType": "luks2",
        "decryptionKey": "file:///tmp/encryption_key"
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
    "volume_type": "BlockDevice",
    "options": {
        "devicePath": "/tmp/test.img",
        "action": "decryptMount",
        "encryptionType": "luks2",
        "decryptionKey": "file:///tmp/encryption_key",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/luks2ext4-cdh-test"
}
```