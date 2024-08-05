// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	SealedSecretPrefix = "sealed."
)

// Common interface for clients that can unseal secrets
type SecretUnsealer interface {
	UnsealSecret(ctx context.Context, secret string) (string, error)
}

func UnsealEnv(ctx context.Context, su SecretUnsealer, env string) (string, error) {
	unsealedValue, err := su.UnsealSecret(ctx, env)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret from env, err: %w", err)
	}
	return unsealedValue, nil
}

// UnsealFile is a shared function that can be used by any client that satisfies the SecretUnsealer interface
func UnsealFile(ctx context.Context, su SecretUnsealer, sealedFile string) (string, error) {
	contents, err := os.ReadFile(sealedFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("sealed file %s does not exist: %w", sealedFile, err)
		}
		return "", fmt.Errorf("failed to read sealed file %s: %w", sealedFile, err)
	}

	if !strings.HasPrefix(string(contents), SealedSecretPrefix) {
		return "", fmt.Errorf("sealed file %s is not a sealed secret", sealedFile)
	}

	return su.UnsealSecret(ctx, string(contents))
}
