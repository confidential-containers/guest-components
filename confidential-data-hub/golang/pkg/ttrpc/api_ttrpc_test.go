// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/url"
	"testing"

	"github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/ttrpc/mock"
	"github.com/stretchr/testify/assert"
)

func TestCreatecdhTtrpcClient(t *testing.T) {
	assert := assert.New(t)

	mockURL, err := mock.GenerateCDHTtrpcMockVSock()
	assert.NoError(err)
	defer mock.RemoveCDHTtrpcMockVSock(mockURL)

	cdhMockServer := mock.CDHTtrpcMockServer{}
	err = cdhMockServer.Start(mockURL)
	assert.NoError(err)
	defer cdhMockServer.Stop()

	sockurl, err := url.Parse(mockURL)
	assert.NoError(err)

	c, err := CreateCDHTtrpcClient(sockurl.Path)
	assert.NoError(err)
	assert.NotNil(c)
}

func TestTtrpcUnsealEnv(t *testing.T) {
	assert := assert.New(t)

	mockURL, err := mock.GenerateCDHTtrpcMockVSock()
	assert.NoError(err)
	defer mock.RemoveCDHTtrpcMockVSock(mockURL)

	cdhMockServer := mock.CDHTtrpcMockServer{}
	err = cdhMockServer.Start(mockURL)
	assert.NoError(err)
	defer cdhMockServer.Stop()

	sockurl, err := url.Parse(mockURL)
	assert.NoError(err)

	c, err := CreateCDHTtrpcClient(sockurl.Path)
	assert.NoError(err)
	assert.NotNil(c)
	defer c.Close()

	ctx := context.Background()
	resp, err := c.UnsealEnv(ctx, "sealed.111")
	assert.Nil(err)
	assert.Equal("unsealed-value:111", resp)
}
