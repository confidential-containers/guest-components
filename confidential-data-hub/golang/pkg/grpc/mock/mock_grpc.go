// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package mock

import (
	"context"
	"fmt"
	"net"
	"strings"

	cdhgrpc "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhgrpc"
	"google.golang.org/grpc"
)

const (
	SealedSecretPrefix = "sealed."
)

type CDHGrpcMockServerImp struct {
	cdhgrpc.UnimplementedSealedSecretServiceServer
}

func (p *CDHGrpcMockServerImp) UnsealSecret(ctx context.Context, input *cdhgrpc.UnsealSecretInput) (*cdhgrpc.UnsealSecretOutput, error) {
	secret := string(input.GetSecret())
	output := cdhgrpc.UnsealSecretOutput{Plaintext: []byte("unsealed-value:" + strings.TrimPrefix(secret, SealedSecretPrefix))}
	return &output, nil
}

type CDHGrpcMockServer struct {
	CDHGrpcMockServerImp
	listener net.Listener
}

func (cv *CDHGrpcMockServer) grpcRegister(s *grpc.Server) {
	cdhgrpc.RegisterSealedSecretServiceServer(s, &CDHGrpcMockServerImp{})
}

func (cv *CDHGrpcMockServer) Start(socketAddr string) error {
	if socketAddr == "" {
		return fmt.Errorf("Missing Socket Address")
	}

	l, err := net.Listen("tcp", socketAddr)
	if err != nil {
		return err
	}

	cv.listener = l

	grpcServer := grpc.NewServer()
	cv.grpcRegister(grpcServer)

	go func() {
		grpcServer.Serve(l)
	}()

	return nil
}

func (cv *CDHGrpcMockServer) Stop() error {
	if cv.listener == nil {
		return fmt.Errorf("Missing mock hvbrid vsock listener")
	}

	return cv.listener.Close()
}
