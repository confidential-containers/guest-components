ARCH ?= $(shell go env GOARCH)
ifeq ($(ARCH),x86_64)
	ARCH := amd64
endif

RPC ?= grpc
DESTDIR ?= /usr/local/bin
BIN_NAME := cdh-go-client

.PHONY: build test install clean

build:
	@echo "Building Go binaries..."
ifeq ($(RPC),grpc)
	GOARCH=$(ARCH) go build -o bin/$(BIN_NAME) ./cmd/$(RPC)-client
else
	$(error ERROR: Unsupported RPC type $(RPC)!)
endif

test:
	@echo "Running unit tests..."
	go test ./...

install:
	@echo "Installing binaries..."
	install -D -m0755 bin/$(BIN_NAME) $(DESTDIR)
	
clean:
	@echo "Cleaning object files and cached files..."
	go clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [ARCH=(x86_64)] [RPC=(grpc)]"
	@echo "install: make install [DESTDIR=/path/to/targets]"
	@echo "test: make test"
	@echo "clean: make clean"
