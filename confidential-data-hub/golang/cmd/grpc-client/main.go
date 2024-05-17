// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	cdhgrpcapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/grpc"
)

func main() {

	vFlag := flag.String("v", "", "sealed secret value")
	fFlag := flag.String("f", "", "sealed secret file")

	flag.Parse()

	c, err := cdhgrpcapi.CreateCDHGrpcClient(cdhgrpcapi.CDHGrpcSocket)
	if err != nil {
		fmt.Printf("failed to create cdh client %v", err)
		os.Exit(1)
	}
	defer c.Close()
	if *vFlag != "" {
		unsealedValue, err := c.UnsealEnv(context.Background(), *vFlag)
		if err != nil {
			fmt.Printf("failed to get unsealed value! err = %v", err)
			os.Exit(1)
		}
		fmt.Printf("unsealed value from env = %s", unsealedValue)
	}
	if *fFlag != "" {
		unsealedValue, err := c.UnsealFile(context.Background(), *fFlag)
		if err != nil {
			fmt.Printf("failed to get unsealed value! err = %v", err)
			os.Exit(1)
		}
		fmt.Printf("unsealed value from file = %s", unsealedValue)
	}
}
