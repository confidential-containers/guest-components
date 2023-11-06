# Secure Storage

## Purpose
The Purpose of this secure storage feature is:
1. Mounting external storage from guest instead of host which would then share it to guest, this is due to performance consideration.
2. The unencrypted data in storage could only be accessed within TEE, that is why we call it secure storage.

## Architecture
![architecture](./images/secure_storage.png)

First of all, the sensitive information of external storage is sealed by the key from KBS/KMS, and store in [sealed secret](https://github.com/confidential-containers/guest-components/blob/main/confidential-data-hub/docs/SEALED_SECRET.md). The sensitive information includes access key id/access key secret to storage, the encryption key of the data(such as AI model) stored in the storage, which also means we supported client encryption.
We reuse [direct block device assigned volume feature](https://github.com/kata-containers/kata-containers/blob/main/docs/design/direct-blk-device-assignment.md) to mount external storage from guest directly. CSI plugin, such as [alibaba cloud OSS CSI plugin](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/blob/master/docs/oss.md) reads the sensitve information from sealed secret and pass it to kata agent. When secure mount service in CDH receives secure mount request, it calls sealed secret service to unseal the sensitive information mentioned above, this process could be based on remote attestation. If success, the secure mount service would use the unsealed sensitive information to mount the external storage and decrypt the data in storage.

