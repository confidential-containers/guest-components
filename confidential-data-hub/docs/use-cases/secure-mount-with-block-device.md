# Secure mount with Block Device

This guide helps an user to use confidential data hub to secure mount inside TEE environment.

## Preliminaries

- Ensure that [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/) is installed.

## Example

### Create a loop device

```shell
$ loop_file="/tmp/test.img"
$ sudo dd if=/dev/zero of=$loop_file bs=1M count=1000
$ sudo losetup -fP $loop_file
$ device=$(sudo losetup -j $loop_file | awk -F'[: ]' '{print $1}')
$ echo $device
# Output should be something like /dev/loop0
$ device_num=$(sudo lsblk -no MAJ:MIN $device)
$ echo $device_num
# Output should be something like 7:0
```

### Secure mount inside a TEE environment

1. Build the CDH and its client tool

Follow the instructions in the [CDH README](../../README.md#confidential-data-hub) and [Client Tool README](../../README.md#client-tool) to build the CDH and its client tool.

2. Install `luks-encrypt-storage`

Install [luks-encrypt-storage](../../storage/scripts/luks-encrypt-storage) into `/usr/local/bin`

3. Run CDH
```shell
$ confidential-data-hub
```

4. Prepare a request JSON `storage.json`
```json
{
    {
        "volume_type": "BlockDevice",
        "options": {
            "deviceId": "7:0",
            "encryptType": "LUKS",
            "dataIntegrity": "true"
        },
        "flags": [],
        "mount_point": "/mnt/test-path"
    }
}

```
- Fields:
    - `volume_type`: The secure mount plugin type name. It determines how the rest of the fields are used.
    - `options`: A key-value map specifying the settings for the mount operation. Different plugins can define different keys in the options. In this example, all keys are for block devices.
    - `flags`: A string list specifying settings for the mount operation. Different plugins can define different uses for this field.
    - `mount_point`: The target mount path for the operation.

- Options Fields:
    - `deviceId`: The device number, formatted as "MAJ:MIN".
    - `encryptType`: The encryption type. Currently, only LUKS is supported.
    - `encryptKey`: Encryption key. It can be a sealed secret or a resource uri. If not set, it means that the device is unencrypted and a random 4096-byte key will be generated to encrypt the device.
    - `dataIntegrity`: Enables dm-integrity to protect data integrity. Note that enabling data integrity will reduce IO performance by more than 30%.

5. Make a request to CDH
```shell
$ client-tool secure-mount --storage-path storage.json

# Check the target path to see if the mount succeeded
$ lsblk |grep "encrypted_disk"
# Expected output:
└─encrypted_disk_OEyEj_dif 253:1    0 968.6M  0 crypt
  └─encrypted_disk_OEyEj   253:2    0 968.6M  0 crypt /mnt/test-path
```