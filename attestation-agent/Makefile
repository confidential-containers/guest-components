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
BIN_NAME := attestation-agent

SOURCE_ARCH := $(shell uname -m)

ARCH ?= $(shell uname -m)
DEBUG ?=
LIBC ?= gnu
ttrpc ?=
grpc ?=
DESTDIR ?= $(PREFIX)/bin
RUSTFLAGS_ARGS ?=
binary ?=
binary_name ?=
OPENSSL ?=

ifeq ($(SOURCE_ARCH), ppc64le)
  ARCH=powerpc64le
endif

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  OPENSSL=1
endif

ifeq ($(ARCH), s390x)
    ATTESTER ?= se-attester
else ifeq ($(ARCH), aarch64)
    ATTESTER ?= cca-attester
else
    ATTESTER ?= all-attesters
endif

ifeq ($(ttrpc), false)
    binary = --bin grpc-aa
    binary_name = grpc-aa
    RPC = grpc
else
    binary = --bin ttrpc-aa
    binary_name = ttrpc-aa
    RPC = ttrpc
endif

ifdef OPENSSL
    CRYPTO := openssl
else
    CRYPTO := rust-crypto
endif

ifeq ($(ATTESTER), none)
    AA_FEATURES := kbs,coco_as,bin,$(RPC),$(CRYPTO)
    AA_CHECK_FEATURES := kbs,coco_as,bin,ttrpc,grpc,$(CRYPTO)
    ATTESTER_PKG_FEATURES := bin
    KBC_FEATURES := cc_kbc,$(CRYPTO)
    KBS_PROTOCOL_FEATURES := background_check,passport,$(CRYPTO),bin,aa_ttrpc,pqc-experimental
else
    AA_FEATURES := kbs,coco_as,bin,$(RPC),$(CRYPTO),$(ATTESTER)
    AA_CHECK_FEATURES := kbs,coco_as,bin,ttrpc,grpc,$(CRYPTO),$(ATTESTER)
    ATTESTER_PKG_FEATURES := $(ATTESTER),bin
    KBC_FEATURES := cc_kbc,$(ATTESTER),$(CRYPTO)
    KBS_PROTOCOL_FEATURES := background_check,passport,$(CRYPTO),$(ATTESTER),bin,aa_ttrpc,pqc-experimental
endif

ifeq ($(LIBC), musl)
    ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
        $(error ERROR: Attestation agent does not support building with the musl libc target for s390x and ppc64le architectures!)
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
	cd attestation-agent && $(RUST_FLAGS) cargo build $(release) --no-default-features --features "$(AA_FEATURES)" $(binary) $(LIBC_FLAG)
	mv $(TARGET_DIR)/$(binary_name) $(TARGET)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

lint:
	cargo clippy -p attestation-agent --all-targets --no-default-features --features "$(AA_CHECK_FEATURES)" -- -D warnings
	cargo clippy -p attester --all-targets --no-default-features --features "$(ATTESTER_PKG_FEATURES)" -- -D warnings
	cargo clippy -p coco_keyprovider --all-targets -- -D warnings
	cargo clippy -p kbc --all-targets --no-default-features --features "$(KBC_FEATURES)" -- -D warnings
	cargo clippy -p kbs_protocol --all-targets --no-default-features \
		--features "$(KBS_PROTOCOL_FEATURES)" -- -D warnings
	cargo clippy -p crypto --all-targets --no-default-features --features $(CRYPTO) -- -D warnings
	cargo clippy -p resource_uri --all-targets -- -D warnings

test:
	cargo test -p attestation-agent --all-targets --no-default-features --features "$(AA_CHECK_FEATURES)"
	cargo test -p attester --all-targets --no-default-features --features "$(ATTESTER_PKG_FEATURES)"
	cargo test -p coco_keyprovider --all-targets
	cargo test -p kbc --all-targets --no-default-features --features "$(KBC_FEATURES)"
	cargo test -p kbs_protocol --all-targets --no-default-features \
		--features "$(KBS_PROTOCOL_FEATURES)"
	cargo test -p crypto --all-targets --no-default-features --features $(CRYPTO)
	cargo test -p resource_uri --all-targets

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)/$(BIN_NAME)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build/lint/test share ATTESTER and OPENSSL (ARCH picks the default attester)"
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x/ppc64le)] [OPENSSL=1] [ATTESTER=all-attesters]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
