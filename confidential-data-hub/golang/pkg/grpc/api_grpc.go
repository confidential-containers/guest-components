// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"fmt"

	cdhapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	CDHGrpcSocket      = "127.0.0.1:8043"
	SealedSecretPrefix = "sealed."
)

type cdhGrpcClient struct {
	conn               *grpc.ClientConn
	sealedSecretClient cdhapi.SealedSecretServiceClient
	secureMountClient  cdhapi.SecureMountServiceClient
}

func CreateCDHGrpcClient(sockAddress string) (*cdhGrpcClient, error) {
	conn, err := grpc.Dial(sockAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cdh sock %q: %w", sockAddress, err)
	}

	sealedSecretClient := cdhapi.NewSealedSecretServiceClient(conn)
	securelMountClient := cdhapi.NewSecureMountServiceClient(conn)

	c := &cdhGrpcClient{
		conn:               conn,
		sealedSecretClient: sealedSecretClient,
		secureMountClient:  securelMountClient,
	}
	return c, nil
}

func (c *cdhGrpcClient) Close() error {
	return c.conn.Close()
}

func (c *cdhGrpcClient) UnsealSecret(ctx context.Context, secret string) (string, error) {
	input := cdhapi.UnsealSecretInput{Secret: []byte(secret)}
	output, err := c.sealedSecretClient.UnsealSecret(ctx, &input)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret: %w", err)
	}

	return string(output.GetPlaintext()[:]), nil
}

func (c *cdhGrpcClient) SecureMount(ctx context.Context, volume_type string, options map[string]string, flags []string, mountpoint string) (string, error) {
	input := cdhapi.SecureMountRequest{VolumeType: volume_type, Options: options, Flags: flags, MountPoint: mountpoint}
	output, err := c.secureMountClient.SecureMount(ctx, &input)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret: %w", err)
	}

	return output.GetMountPath(), nil
}
