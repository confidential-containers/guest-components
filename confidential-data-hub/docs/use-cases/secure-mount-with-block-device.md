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
        "encryptType": "luks2",
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
    - `encryptType`: **Required**. The encryption type. Currently, only `luks2` is supported.
    - `encryptKey`: **Optional**. Encryption key. It can be a sealed secret `sealed.xxx`, a resource uri `kbs:///...` or a local path `file:///...`. If not set, it means that the device is unencrypted and a random 4096-byte key will be generated to encrypt the device.
    - `ephemeral`: **Optional**. Indicates whether the block device is ephemeral. If set to `true`, an extra luks2 encryption operation will be performed upon the device, which means all existing data will be overwritten. Also, the block device will be formatted with the given `filesystemType` and mounted to the target path if `filesystemType` is set. If set to `false`, no extra luks2 encryption and filesystem format will be formatted before mounting.
    - `filesystemType`: **Optional**. Format the block device with a filesystem type. If given, the device will be formatted with the given filesystem type and mounted to the target path. If not set, the block device will be mounted as a raw device. Only `ext4` is supported.
    - `dataIntegrity`: **Optional**. Enables dm-integrity to protect data integrity. Note that enabling data integrity will reduce IO performance by more than 30%. Accepted values are `true` or `false`. Default is `false`.

5. Make a request to CDH
```shell
$ client-tool secure-mount --storage-path storage.json

# Check the target path to see if the mount succeeded
$ lsblk |grep "encrypted_disk"
# Expected output:
└─encrypted_disk_OEyEj_dif 253:1    0 968.6M  0 crypt
  └─encrypted_disk_OEyEj   253:2    0 968.6M  0 crypt /mnt/test-path
```

### Best Practices

#### Ephemeral Storage

Ephemeral storage is a storage that is not persistent.

1. Mount a block device file, encrypt it using `luks2` with an ephemeral key, and mount the plaintext device to `/mnt/dev-path` as a file.

```json
{
    "volume_type": "BlockDevice",
    "options": {
        "devicePath": "/dev/some-device",
        "ephemeral": "true",
        "encryptType": "luks2"
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
        "encryptType": "luks2",
        "ephemeral": "true",
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
        "encryptType": "luks2",
        "encryptKey": "file:///tmp/encryption_key"
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
        "encryptType": "luks2",
        "encryptKey": "file:///tmp/encryption_key",
        "filesystemType": "ext4"
    },
    "flags": [],
    "mount_point": "/mnt/luks2ext4-cdh-test"
}
```