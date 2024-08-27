# Confidential Data Hub Golang Client

## Overview
This offers a streamlined client interface for engaging with Confidential Data Hub (`CDH`) through both gRPC and TTRPC protocols. Used for integration into Go-based projects, it’s ideal for applications like the Node Resource Interface (`NRI`) or image verifiers plugins in containerd. Furthermore, it can be compiled into a client binary for direct interaction with `CDH`.

## Getting Started

### Install dependencies

```bash
$ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
$ go install github.com/containerd/ttrpc/cmd/protoc-gen-go-ttrpc@latest
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
$ go install github.com/containerd/protobuild@latest
```

### Usage as library

Import the package into your Go project:

```go
//common interface
import common "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/core"

//grpc package 
import cdhgrpc "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/grpc"
//ttrpc package 
import cdhttrpc "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/ttrpc"
```

Create a new client instance:

```go
//cdh grpc client
c, err := cdhgrpc.CreateCDHGrpcClient("127.0.0.1:8043")

//cdh ttrpc client
c, err := cdhttrpc.CreateCDHTtrpcClient("/run/confidential-containers/cdh.sock")
```

### Usage as binary

Build and Install the binary, such as:
```bash
$ make build RPC=grpc
Generating Go code...
protoc -I.:/root/go/src:/usr/local/include:/usr/include --go_out=/root/go/src --go_opt=Mgithub.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/api.proto=github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhapi --go-grpc_out=/root/go/src /root/go/src/github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/api.proto
/root/go/src/github.com/confidential-containers/guest-components/confidential-data-hub/golang
Building Go binaries...
$ sudo make install
Installing binaries...
install -D -m0755 bin/cdh-go-client /usr/local/bin
```

### Supported Operations

- UnsealSecret
- SecureMount

#### UnsealSecret

Interact with `CDH` using the library :
```go
unsealedValue, err := common.UnsealEnv(ctx, c, sealedSecret)
```

Interact with CDH using the binary:
```bash
$ cdh-go-client -o UnsealSecret -I UnsealEnv -socket "127.0.0.1:8043" -i sealed.fakeheader.ewogICJ2ZXJzaW9uIjogIjAuMS4wIiwKICAidHlwZSI6ICJ2YXVsdCIsCiAgIm5hbWUiOiAia2JzOi8vL2RlZmF1bHQvdHlwZS90YWciLAogICJwcm92aWRlciI6ICJrYnMiLAogICJwcm92aWRlcl9zZXR0aW5ncyI6IHt9LAogICJhbm5vdGF0aW9ucyI6IHt9Cn0K.fakesignature
Client rpc type: grpc
unsealed value from env = that's the unsealed secret
```
or get sealed secret from file:
```bash
$ cat <<EOF > sealedsecretfile
sealed.fakeheader.ewogICJ2ZXJzaW9uIjogIjAuMS4wIiwKICAidHlwZSI6ICJ2YXVsdCIsCiAgIm5hbWUiOiAia2JzOi8vL2RlZmF1bHQvdHlwZS90YWciLAogICJwcm92aWRlciI6ICJrYnMiLAogICJwcm92aWRlcl9zZXR0aW5ncyI6IHt9LAogICJhbm5vdGF0aW9ucyI6IHt9Cn0K.fakesignature
EOF
$ cdh-go-client -o UnsealSecret -I UnsealFile -socket "127.0.0.1:8043" -i sealedsecretfile 
Client rpc type: grpc
unsealed value from file = that's the unsealed secret
```

#### SecureMount

Interact with `CDH` using the library:

```go
mountPath, err := common.SecureMount(ctx, c, volume_type, options, flags, mountpoint)
```

Interact with `CDH` using the binary:

```bash
cat <<EOF > securemount.json
{
    "volume_type": "BlockDevice",
    "options": {
        "deviceId": "7:0",
        "encryptType": "LUKS",
        "dataIntegrity": "true"
    },
    "flags": [],
    "mountpoint": "/tmp/cdh-test"
}
EOF
$ cdh-go-client -o SecureMount --socket /run/confidential-containers/cdh.sock -i ./test.json
Successfully secure mount to /tmp/cdh-test

# Verify the mount:

$ lsblk --fs
NAME      FSTYPE      FSVER    LABEL UUID                                   FSAVAIL FSUSE% MOUNTPOINTS
loop0     crypto_LUKS 2              ee0897ec-0f0f-4f11-a1f0-38bfe3120ad1                  
└─encrypted_disk_qMSEu_dif
                                                                                           
  └─encrypted_disk_qMSEu
                                                                             870.6M     0% /tmp/cdh-test

$ cryptsetup status encrypted_disk_qMSEu
/dev/mapper/encrypted_disk_qMSEu is active and is in use.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 768 bits
  key location: keyring
  integrity: hmac(sha256)
  integrity keysize: 256 bits
  device:  /dev/loop0
  loop:    /tmp/cdh-test-volume.img
  sector size:  4096
  offset:  0 sectors
  size:    1983768 sectors
  mode:    read/write

```