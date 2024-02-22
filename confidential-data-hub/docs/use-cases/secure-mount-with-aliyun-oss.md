# Secure mount with Aliyun OSS

This guide helps an user
- Create a storage with client-side encrypted using gocrypt-fs and upload to aliyun OSS
- Use confidential data hub to secure mount inside TEE environment

## Preliminaries

Users should prepare the following
- An [OSS storage](https://www.alibabacloud.com/product/object-storage-service?spm=a3c0i.23458820.2359477120.62.94807d3f6Q2Oqb) service and an OSS bucket with id e.g. `<bucket-id>`
- Install [ossutil](https://www.alibabacloud.com/help/en/oss/developer-reference/install-ossutil) and [ossfs](https://github.com/aliyun/ossfs), tools to interactive with OSS
- Suppose the OS is ubuntu.

## Steps 

There are two modes, [Plaintext data in OSS](../SECURE_STORAGE.md#plaintext-data-in-oss) and [Ciphertext data in OSS](../SECURE_STORAGE.md#ciphertext-data-in-oss). The following steps are for [Ciphertext data in OSS](../SECURE_STORAGE.md#ciphertext-data-in-oss). If users want to use [Plaintext data in OSS](../SECURE_STORAGE.md#plaintext-data-in-oss) mode, just skip the gocryptfs encryption parts and directly upload the plaintext of data with `ossutil`.

### Create the gocryptfs and upload to the OSS storage

Firstly, install golang and gocryptfs
```shell
# Install golang
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install gocryptfs
git clone https://github.com/rfjakob/gocryptfs.git
cd gocryptfs
./build-without-openssl.bash
sudo apt install libssl-dev
```

Prepare a password `<PASSWORD>` used by gocryptfs to encrypt the contents
```shell
mkdir -p /path/to/workspace
cd /path/to/workspace
echo <PASSWORD> > password
```

Create a gocryptfs working directory
```shell
mkdir cipher plain

cat password | gocryptfs -init cipher
cat password | gocryptfs cipher plain
```

Then, move any data to be encrypted to path `/path/to/workspace/plain`.
At the same time, the data will be encrypted automatically by gocryptfs.
The ciphertext will be under `/path/to/workspace/cipher`.

Then, upload the ciphertext (the whole directory `/path/to/workspace/cipher`) to OSS storage bucket
```shell
ossutil64 cp -r /path/to/workspace/cipher oss://<bucket-id>/<bucket-path>
```

### Secure mount inside a TEE environment

Firstly, build the [CDH client tool](../../README.md#client-tool) and [CDH](../../README.md#confidential-data-hub).

Ensure `gocryptfs` and `ossfs` are both installed into `/usr/local/bin`.

Run CDH
```shell
confidential-data-hub
```

Prepare a request JSON `storage.json`
```json
{
    "driver": "",
    "driver_options": [
        "alibaba-cloud-oss={\"akId\":\"XXX\",\"akSecret\":\"XXX\",\"annotations\":\"\",\"bucket\":\"<bucket-id>\",\"encrypted\":\"gocryptfs\",\"encPasswd\":\"<PASSWORD>\",\"kmsKeyId\":\"\",\"otherOpts\":\"-o max_stat_cache_size=0 -o allow_other\",\"path\":\"<bucket-path>\",\"readonly\":\"\",\"targetPath\":\"/mnt/aliyun-oss\",\"url\":\"https://oss-cn-beijing.aliyuncs.com\",\"volumeId\":\"\"}"
    ],
    "source": "",
    "fstype": "",
    "options": [],
    "mount_point": "/mnt/target-path"
}
```
- `mount_point`: the target path to mount the decrypted storage.

The only string member of `driver_options` looks like `alibaba-cloud-oss=XXX`. `XXX` here is an escaped JSON object.
```json
{
    "akId": "XXX",
    "akSecret": "XXX",
    "annotations": "",
    "bucket": "<bucket-id>",
    "encrypted": "gocryptfs",
    "encPasswd": "<PASSWORD>",
    "kmsKeyId": "",
    "otherOpts": "-o max_stat_cache_size=0 -o allow_other",
    "path": "/<bucket-path>",
    "readonly": "",
    "targetPath": "/mnt/aliyun-oss",
    "url": "https://oss-cn-beijing.aliyuncs.com",
    "volumeId": ""
}
```

The fields here
- `akId`: is Id of AK to access the OSS bucket. This will be provided when creating the OSS bucket. This can also be a [sealed secret](../SEALED_SECRET.md).
- `akSecret`: is plaintext of AK to access the OSS bucket. This will be provided when creating the OSS bucket. This can also be a [sealed secret](../SEALED_SECRET.md).
- `annotations`: empty.
- `bucket`: the id of OSS bucket, s.t. `<bucket-id>`.
- `encrypted`: if is set `gocryptfs`, it means that `gocryptfs` will be used to decrypt the oss storage and the plaintext will be mounted to `targetPath`. Else (like leave empty), it means the oss storage will be directly mounted to the `targetPath`.
- `encPasswd`: If `encrypted` is set `gocryptfs`, this field should be the password when encrypting using `gocryptfs`. This field can also be a [sealed secret](../SEALED_SECRET.md).
- `kmsKeyId`: empty.
- `otherOpts`: Other options when mount oss storage.
- `path`: The path in OSS bucket, s.t. `/<bucket-path>`.
- `readonly`: empty.
- `targetPath`: This field is not used.
- `url`: The URL of the OSS storage service. In this example, the oss service is in Beijing, CN. This can be selected when creating the OSS bucket.
- `volumeId`: empty.

:warning: **Warning:** If any [sealed secret](../SEALED_SECRET.md) is used, the CDH will try to access the relative KMS service (probably KBS).

Make request to CDH
```shell
client-tool secure-mount --storage-path storage.json

# Check the target path to see if mount succeeds
ls /mnt/aliyun-oss
```