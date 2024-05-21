ARCH ?= $(shell go env GOARCH)
ifeq ($(ARCH),x86_64)
	ARCH := amd64
endif

RPC ?= grpc
DESTDIR ?= /usr/local/bin
PROTODIR = $(CURDIR)/../hub/protos
BIN_NAME := cdh-go-client

.PHONY: generate build test install clean

generate:
	@echo "Generating Go code..."
ifeq ($(RPC), $(filter $(RPC), grpc ttrpc))
	@cp ../hub/protos/api.proto ./pkg/api/api.proto
	@sed -i 's/generators = \["go", ".*"\]/generators = ["go", "go-$(RPC)"]/' ./pkg/api/Protobuild.toml
	@cd pkg/api/ && protobuild github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api && cd -
else
	$(error ERROR: Unsupported RPC type $(RPC)!)
endif

build: generate
	@echo "Building Go binaries..."
ifeq ($(RPC), $(filter $(RPC), grpc ttrpc))
	GOARCH=$(ARCH) go build -ldflags "-X main.clientType=$(RPC)" -o bin/$(BIN_NAME) ./cmd/$(RPC)-client
else
	$(error ERROR: Unsupported RPC type $(RPC)!)
endif

test: generate
	@echo "Running unit tests..."
ifeq ($(RPC), $(filter $(RPC), grpc ttrpc))
	go test ./pkg/$(RPC)
else
	$(error ERROR: Unsupported RPC type $(RPC)!)
endif

install:
	@echo "Installing binaries..."
	install -D -m0755 bin/$(BIN_NAME) $(DESTDIR)
	
clean:
	@echo "Cleaning object files and cached files..."
	go clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [ARCH=(x86_64)] [RPC=(ttrpc/grpc)]"
	@echo "install: make install [DESTDIR=/path/to/targets]"
	@echo "test: make test"
	@echo "clean: make clean"
