PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local

ifeq ($(shell test -e /etc/debian_version && echo -n yes),yes)
    DEBIANOS = true
else
    DEBIANOS = false
endif

$(info DEBIANOS is: $(DEBIANOS))

TARGET_DIR := ../target
BIN_NAME := confidential-data-hub

ONE_SHOT ?= false

SOURCE_ARCH := $(shell uname -m)
RPC ?= ttrpc
ARCH ?= $(shell uname -m)
DEBUG ?=
ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
    LIBC ?= gnu
else
    LIBC ?= musl
endif
RESOURCE_PROVIDER ?= kbs,sev
KMS_PROVIDER ?= aliyun,ehsm
DESTDIR ?= $(PREFIX)/bin
RUSTFLAGS_ARGS ?=
features ?=

binary_name ?=

ifeq ($(ONE_SHOT), true)
    binary = --bin cdh-oneshot
    features += bin
    binary_name = cdh-oneshot
else ifeq ($(RPC), ttrpc)
    binary = --bin ttrpc-cdh
    features += bin,ttrpc
    binary_name = ttrpc-cdh
else
    binary = --bin grpc-cdh
    features += bin,grpc
    binary_name = grpc-cdh
endif

ifeq ($(SOURCE_ARCH), ppc64le)
  ARCH=powerpc64le
endif

ifneq ($(RESOURCE_PROVIDER), none)
    features += $(RESOURCE_PROVIDER)
endif

ifneq ($(KMS_PROVIDER), none)
    features += $(KMS_PROVIDER)
endif

ifeq ($(LIBC), musl)
    ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
        $(error ERROR: Confidential Data Hub does not support building with the musl libc target for s390x and ppc64le architectures!)
    endif
    MUSL_ADD := $(shell rustup target add ${ARCH}-unknown-linux-musl)
    ifeq ($(DEBIANOS), true)
        MUSL_INSTALL := $(shell sudo apt-get install -y musl-tools) 
    endif
endif

ifneq ($(SOURCE_ARCH), $(ARCH))
    # SOURCE_ARCH and target architecture(ARCH) are different on ppc64le
    ifeq ($(SOURCE_ARCH), ppc64le)
        $(info INFO: Ignore cross-compiling when SOURCE_ARCH is ppc64le)
    else ifeq ($(DEBIANOS), true)
        GCC_COMPILER_PACKAGE_FOR_TARGET_ARCH := gcc-$(ARCH)-linux-$(LIBC)
        GCC_COMPILER_FOR_TARGET_ARCH := $(ARCH)-linux-$(LIBC)-gcc
        RUSTC_TARGET_FOR_TARGET_ARCH := $(ARCH)-unknown-linux-$(LIBC)
        GCC_FOR_TARGET_ARCH_INSTALL := $(shell sudo apt-get install -y ${GCC_COMPILER_PACKAGE_FOR_TARGET_ARCH})
        RUST_TARGET_FOR_TARGET_ARCH_INSTALL := $(shell rustup target add ${RUSTC_TARGET_FOR_TARGET_ARCH})
        RUSTFLAGS_ARGS += -C linker=$(GCC_COMPILER_FOR_TARGET_ARCH)
    else
        $(error ERROR: Cross-compiling is only tested on Debian-like OSes)
    endif
endif

ifeq ($(SOURCE_ARCH), $(filter $(SOURCE_ARCH), s390x ppc64le))
    ifeq ($(DEBIANOS), true)
        PROTOC_BINARY_INSTALL := $(shell sudo apt-get install -y protobuf-compiler)  
    endif
endif

LIBC_FLAG := --target $(ARCH)-unknown-linux-$(LIBC)
TARGET_DIR := $(TARGET_DIR)/$(ARCH)-unknown-linux-$(LIBC)

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

ifneq ($(RUSTFLAGS_ARGS),)
    RUST_FLAGS := RUSTFLAGS="$(RUSTFLAGS_ARGS)"
endif

build:
	cd hub && $(RUST_FLAGS) cargo build $(release) --no-default-features --features "$(features)" $(binary) $(LIBC_FLAG)
	mv $(TARGET_DIR)/$(binary_name) $(TARGET)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)/$(BIN_NAME)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x/ppc64le)] [RESOURCE_PROVIDER=(kbs/sev)] [KMS_PROVIDER=aliyun/ehsm] [RPC=(ttrpc/grpc)]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
