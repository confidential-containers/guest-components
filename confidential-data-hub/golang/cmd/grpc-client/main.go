// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	common "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/core"
	cdhgrpcapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/grpc"
)

var (
	clientType string // set by the compiler
)

func main() {
	fmt.Printf("Client rpc type: %s\n", clientType)

	common.Init()
	flag.Parse()

	c, err := cdhgrpcapi.CreateCDHGrpcClient(common.Socket)
	if err != nil {
		fmt.Printf("failed to create cdh client %v", err)
		os.Exit(1)
	}
	defer c.Close()

	// The client currently supports only UnsealSecret operation.
	// We need to implement the following operations: GetResource, SecureMount, and UnwrapKey.
	switch common.OperationType {
	case "UnsealSecret":
		if common.OperationInterface == "UnsealEnv" {
			unsealedValue, err := common.UnsealEnv(context.Background(), c, common.OperationInput)
			if err != nil {
				fmt.Printf("failed to get unsealed value! err = %v", err)
				os.Exit(1)
			}
			fmt.Printf("unsealed value from env = %s", unsealedValue)
		} else {
			unsealedValue, err := common.UnsealFile(context.Background(), c, common.OperationInput)
			if err != nil {
				fmt.Printf("failed to get unsealed value! err = %v", err)
				os.Exit(1)
			}
			fmt.Printf("unsealed value from file = %s", unsealedValue)
		}
	default:
		fmt.Printf("The operation type %s is not support yet", common.OperationType)
		os.Exit(1)
	}
}
