// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"

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
	resp, err := c.UnsealEnv(ctx, "sealed.111")
	assert.Nil(err)
	assert.Equal("unsealed-value:111", resp)
}
