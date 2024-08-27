// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package mock

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

	cdhapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhapi"
	"github.com/containerd/ttrpc"
)

const (
	ttrpcVSockPrefix   = "mock://"
	SealedSecretPrefix = "sealed."
)

var testCDHTtrpcMockVSockURLTempl = ttrpcVSockPrefix + "%s/cdh.sock"

func GenerateCDHTtrpcMockVSock() (string, error) {
	dir, err := os.MkdirTemp("", "cdh-vsock-test")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(testCDHTtrpcMockVSockURLTempl, dir), nil
}

func RemoveCDHTtrpcMockVSock(sockAddress string) error {
	if !strings.HasPrefix(sockAddress, ttrpcVSockPrefix) {
		return fmt.Errorf("Invalid socket address: %s", sockAddress)
	}

	sockPath := strings.TrimPrefix(sockAddress, ttrpcVSockPrefix)
	return os.RemoveAll(path.Dir(sockPath))
}

type CDHTtrpcMockServer struct {
	CDHTtrpcMockServerImp

	listener net.Listener
}

func (cv *CDHTtrpcMockServer) ttrpcRegister(s *ttrpc.Server) {
	cdhapi.RegisterSealedSecretServiceService(s, &cv.CDHTtrpcMockServerImp)
	cdhapi.RegisterSecureMountServiceService(s, &cv.CDHTtrpcMockServerImp)
}

func (cv *CDHTtrpcMockServer) Start(socketAddr string) error {
	if socketAddr == "" {
		return fmt.Errorf("Missing Socket Address")
	}

	url, err := url.Parse(socketAddr)
	if err != nil {
		return err
	}

	l, err := net.Listen("unix", url.Path)
	if err != nil {
		return err
	}

	cv.listener = l

	ttrpcServer, err := ttrpc.NewServer()
	if err != nil {
		return err
	}
	cv.ttrpcRegister(ttrpcServer)

	go func() {
		ttrpcServer.Serve(context.Background(), l)
	}()

	return nil
}

func (cv *CDHTtrpcMockServer) Stop() error {
	if cv.listener == nil {
		return fmt.Errorf("Missing mock hvbrid vsock listener")
	}

	return cv.listener.Close()
}

type CDHTtrpcMockServerImp struct{}

func (p *CDHTtrpcMockServerImp) UnsealSecret(ctx context.Context, input *cdhapi.UnsealSecretInput) (*cdhapi.UnsealSecretOutput, error) {
	secret := string(input.GetSecret())
	output := cdhapi.UnsealSecretOutput{Plaintext: []byte("unsealed-value:" + strings.TrimPrefix(secret, SealedSecretPrefix))}
	return &output, nil
}

func (p *CDHTtrpcMockServerImp) SecureMount(ctx context.Context, input *cdhapi.SecureMountRequest) (*cdhapi.SecureMountResponse, error) {
	mountpoint := input.GetMountPoint()
	output := cdhapi.SecureMountResponse{MountPath: mountpoint}
	return &output, nil
}
