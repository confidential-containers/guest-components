# Pull image with Nydus (Deprecated)

> [!NOTE]
> Nydus is not supported in image-rs anymore. This document will be deleted soon.

## Prepare the environments

### 1. Install All Nydus Binaries
Nydus binaries are required to convert container images or directories to (encrypted) Nydus images. Follow the instructions to install Nydus.

Get `nydus-image`, `nydusd`, `nydusify`, `nydusctl` and `nydus-overlayfs` binaries from [release](https://github.com/dragonflyoss/image-service/releases) page.

```shell
sudo install -D -m 755 nydusd nydus-image nydusify nydusctl nydus-overlayfs /usr/bin
```

### 2. Deploy and Configure CoCo Key Broker System cluster
A tenant-side CoCo Key Broker System cluster includes:
* Key Broker Service (KBS): Brokering service for confidential resources.
* Attestation Service (AS): Verifier for remote attestation.
* Reference Value Provicer Service (RVPS): Provides reference values for AS.
* CoCo Keyprovider: Component to encrypt the images following ocicrypt spec.

We will use the Key Broker System cluster to encrypt the image.
Follow the [instructions](https://github.com/confidential-containers/confidential-containers/blob/main/quickstart.md#deploy-and-configure-tenant-side-coco-key-broker-system-cluster) to prepare CoCo Key Broker System.

----

## Generate encrypted Nydus image
Use `nydusify` and `nydus-image` to convert OCI container images to encrypted nydus image with KBS cluster.
Use busybox:latest for example:

```shell
cat > ocicrypt.conf << EOF
{
    "key-providers": {
        "attestation-agent": {
            "grpc": "127.0.0.1:50000"
        }
    }
}
EOF
```

```shell
OCICRYPT_KEYPROVIDER_CONFIG=ocicrypt.conf \
nydusify convert --source docker.io/library/busybox:latest \
--target [REGISTRY_URL]/busybox:encrypted-nydus \
--encrypt-recipients provider:attestation-agent \
--nydus-image /usr/bin/nydus-image
```

Be sure replace [REGISTRY_URL] with the desired registry URL like `docker.io/myregistry`.

----

## Deploy encrypted Nydus image as a CoCo workload on CC HW
Here is a sample yaml for encrypted Nydus image deploying:

encrypted-image-test-busybox.yaml
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: encrypted-image-test-busybox
spec:
  containers:
  - image: [REGISTRY_URL]/busybox:encrypted-nydus
    name: busybox
  dnsPolicy: ClusterFirst
  runtimeClassName: [RUNTIME_CLASS]
```

Be sure to replace [REGISTRY_URL] with the desired registry URL of the encrypted image generated in previous step, replace [RUNTIME_CLASS] with kata runtime class for CC HW.
Deploy encrypted image as a workload:

```shell
kubectl apply -f encrypted-image-test-busybox.yaml
```

----

## Optimization Result
|Image|Uncompressed Image Size|OCI Image Size|Nydus Image Size|CMD|Time of Creating & Starting Container with Encrypted OCI image|Time of Creating & Starting Container with Encrypted Nydus image|Optimization percentage|
|-|-|-|-|-|-|-|-|
|busybox|4.86MB|2.47MB|2.21MB|top|1.782s|1.904s|-6.8%|
|ubuntu|72.8MB|28.16MB|30.86MB|sh|3.412s|2.167s|36.5%|
|redis|113MB|45.9MB|48.29MB|redis-server|5.214s|2.455s|52.9%|
|nginx|141MB|67.32MB|69.06MB|nginx|6.937s|2.578s|62.8%|
|mysql|516MB|157.98MB|168.33MB|mysqld|16.577s|2.444s|85.3%|
|python|917MB|360.43MB|351.78MB|python|33.531s|2.303s|93.13%|
|node|993MB|380.02MB|363.75MB|node|37.123s|2.257s|93.92%|
|gradle|752MB|396.99MB|395.8MB|gradle|35.767s|2.069s|94.22%| 