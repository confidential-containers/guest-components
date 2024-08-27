// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	common "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/core"
	"github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/grpc/mock"
	"github.com/stretchr/testify/assert"
)

func TestCreatecdhGrpcClient(t *testing.T) {
	assert := assert.New(t)

	cdhMockServer := mock.CDHGrpcMockServer{}
	err := cdhMockServer.Start(":8043")
	assert.NoError(err)
	defer cdhMockServer.Stop()

	c, err := CreateCDHGrpcClient(CDHGrpcSocket)
	assert.NoError(err)
	assert.NotNil(c)
}

func TestGrpcUnsealEnv(t *testing.T) {
	assert := assert.New(t)

	cdhMockServer := mock.CDHGrpcMockServer{}
	err := cdhMockServer.Start(":8043")
	assert.NoError(err)
	defer cdhMockServer.Stop()

	c, err := CreateCDHGrpcClient(CDHGrpcSocket)
	assert.NoError(err)
	assert.NotNil(c)
	defer c.Close()

	ctx := context.Background()
	resp, err := common.UnsealEnv(ctx, c, "sealed.111")
	assert.Nil(err)
	assert.Equal("unsealed-value:111", resp)
}

func TestGrpcUnsealFile(t *testing.T) {
	assert := assert.New(t)

	cdhMockServer := mock.CDHGrpcMockServer{}
	err := cdhMockServer.Start(":8043")
	assert.NoError(err)
	defer cdhMockServer.Stop()

	c, err := CreateCDHGrpcClient(CDHGrpcSocket)
	assert.NoError(err)
	assert.NotNil(c)
	defer c.Close()

	ctx := context.Background()

	tempDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sealedFilePath := filepath.Join(tempDir, "testfile")
	unsealedContent := "unsealed content"
	err = os.WriteFile(sealedFilePath, []byte("sealed."+unsealedContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write sealed file: %v", err)
	}

	resp, err := common.UnsealFile(ctx, c, sealedFilePath)
	assert.Nil(err)
	assert.Equal("unsealed-value:unsealed content", resp)
}

func TestGrpcSecureMount(t *testing.T) {
	assert := assert.New(t)

	cdhMockServer := mock.CDHGrpcMockServer{}
	err := cdhMockServer.Start(":8043")
	assert.NoError(err)
	defer cdhMockServer.Stop()

	c, err := CreateCDHGrpcClient(CDHGrpcSocket)
	assert.NoError(err)
	assert.NotNil(c)
	defer c.Close()

	ctx := context.Background()
	options := map[string]string{"deviceId": "0:1", "encryptType": "LUKS", "dataIntegrity": "True"}
	resp, err := common.SecureMount(ctx, c, "BlockDevice", options, []string{}, "/tmp/test-mount")
	assert.Nil(err)
	assert.Equal("/tmp/test-mount", resp)
}
