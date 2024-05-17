// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	cdhttrpcapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhttrpc"
	"github.com/containerd/ttrpc"
)

const (
	CDHTtrpcSocket     = "/run/confidential-containers/cdh.sock"
	SealedSecretPrefix = "sealed."
)

type cdhTtrpcClient struct {
	conn               net.Conn
	sealedSecretClient cdhttrpcapi.SealedSecretServiceService
}

func CreateCDHTtrpcClient(sockAddress string) (*cdhTtrpcClient, error) {
	conn, err := net.Dial("unix", sockAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cdh sock %q: %w", sockAddress, err)
	}

	ttrpcClient := ttrpc.NewClient(conn)
	sealedSecretClient := cdhttrpcapi.NewSealedSecretServiceClient(ttrpcClient)

	c := &cdhTtrpcClient{
		conn:               conn,
		sealedSecretClient: sealedSecretClient,
	}
	return c, nil
}

func (c *cdhTtrpcClient) Close() error {
	return c.conn.Close()
}

func (c *cdhTtrpcClient) unsealSecret(ctx context.Context, secret string) (string, error) {
	input := cdhttrpcapi.UnsealSecretInput{Secret: []byte(secret)}
	output, err := c.sealedSecretClient.UnsealSecret(ctx, &input)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret: %w", err)
	}

	return string(output.GetPlaintext()[:]), nil
}

func (c *cdhTtrpcClient) UnsealEnv(ctx context.Context, env string) (string, error) {
	unsealedValue, err := c.unsealSecret(ctx, env)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret from env: %w", err)
	}
	return unsealedValue, nil
}

func (c *cdhTtrpcClient) UnsealFile(ctx context.Context, sealedFile string) (string, error) {
	fileInfo, err := os.Stat(sealedFile)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("sealed File %s does not exist", sealedFile)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("sealed File %s is not a regular file", sealedFile)
	}
	contents, err := os.ReadFile(sealedFile)
	if err != nil {
		return "", fmt.Errorf("sealed File %s is failed to read, err = %w", sealedFile, err)
	}

	if strings.HasPrefix(string(contents), SealedSecretPrefix) {
		unsealedValue, err := c.unsealSecret(ctx, string(contents))
		if err != nil {
			return "", fmt.Errorf("failed to unseal secret from file, err: %w", err)
		}
		return unsealedValue, nil
	} else {
		return "", fmt.Errorf("sealed File %s is not a sealed secret", sealedFile)
	}
}
