// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	common "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/core"
	cdhgrpc "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/grpc"
)

var (
	clientType string // set by the compiler
)

func main() {
	fmt.Printf("Client rpc type: %s\n", clientType)

	common.Init()
	flag.Parse()

	c, err := cdhgrpc.CreateCDHGrpcClient(common.Socket)
	if err != nil {
		fmt.Printf("failed to create cdh client %v", err)
		os.Exit(1)
	}
	defer c.Close()

	// The client currently supports only UnsealSecret and SecureMount operation.
	// We need to implement the following operations: GetResource and UnwrapKey.
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
	case "SecureMount":
		input_file_path := common.OperationInput
		jsonInput, err := os.ReadFile(input_file_path)

		var storage common.Storage

		// Unmarshal the JSON data into the struct
		err = json.Unmarshal(jsonInput, &storage)
		if err != nil {
			log.Fatalf("Error unmarshaling JSON: %s", err)
			os.Exit(1)
		}

		mountPath, err := common.SecureMount(context.Background(), c, storage.VolumeType, storage.Options, storage.Flags, storage.Mountpoint)
		if err != nil {
			fmt.Printf("failed to secure mount! err = %v", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully secure mount to %s", mountPath)

	default:
		fmt.Printf("The operation type %s is not support yet", common.OperationType)
		os.Exit(1)
	}
}
