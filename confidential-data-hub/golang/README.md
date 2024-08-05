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

Interact with `CDH` using the client, for example :
```go
unsealedValue, err := common.UnsealEnv(ctx, c, sealedSecret)
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

Interact with CDH using the binary, such as get sealed secret:
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