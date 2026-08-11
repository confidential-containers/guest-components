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
ATTESTER ?=
features ?= coco_as,kbs
OPENSSL ?=

ifeq ($(SOURCE_ARCH), ppc64le)
  ARCH=powerpc64le
endif

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  OPENSSL=1
endif

ifeq ($(ttrpc), false)
    binary = --bin grpc-aa
    features += bin,grpc
    binary_name = grpc-aa
else
    binary = --bin ttrpc-aa
    features += bin,ttrpc
    binary_name = ttrpc-aa
endif

ifdef ATTESTER
    ifneq ($(ATTESTER), none)
        features += $(ATTESTER)
    endif
else
    features += all-attesters
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

ifdef OPENSSL
    features := $(features),openssl
else
    features := $(features),rust-crypto
endif

ifeq ($(ARCH), $(filter $(ARCH), s390x aarch64))
    LINT_OPTION = lint-$(ARCH)
else
    LINT_OPTION = lint-default
endif

build:
	cd attestation-agent && $(RUST_FLAGS) cargo build $(release) --no-default-features --features "$(features)" $(binary) $(LIBC_FLAG)
	mv $(TARGET_DIR)/$(binary_name) $(TARGET)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

lint: $(LINT_OPTION)

lint-default:
	cargo clippy -p attestation-agent --features kbs,coco_as,bin,grpc,ttrpc,all-attesters -- -D warnings
	cargo clippy -p attester --all-targets --features all-attesters,bin -- -D warnings
	cargo clippy -p coco_keyprovider --all-targets -- -D warnings
	cargo clippy -p kbc --all-targets --features cc_kbc,all-attesters,rust-crypto -- -D warnings
	cargo clippy -p kbs_protocol --all-targets --no-default-features \
		--features background_check,passport,rust-crypto,all-attesters,bin,aa_ttrpc -- -D warnings
	cargo clippy -p crypto --all-targets --features rust-crypto -- -D warnings
	cargo clippy -p resource_uri --all-targets -- -D warnings
	cargo clippy -p sev --all-targets -- -D warnings

lint-s390x:
	cargo clippy -p attestation-agent --no-default-features --features openssl,kbs,coco_as,bin,grpc,ttrpc -- -D warnings
	cargo clippy -p attester --all-targets --no-default-features --features se-attester,bin -- -D warnings
	cargo clippy -p coco_keyprovider --all-targets -- -D warnings
	cargo clippy -p kbc --all-targets --no-default-features --features cc_kbc,se-attester,openssl -- -D warnings
	cargo clippy -p kbs_protocol --all-targets --no-default-features \
		--features background_check,passport,openssl,se-attester,bin,aa_ttrpc -- -D warnings
	cargo clippy -p crypto --all-targets --no-default-features --features openssl -- -D warnings
	cargo clippy -p resource_uri --all-targets -- -D warnings
	cargo clippy -p sev --all-targets -- -D warnings

lint-aarch64:
	cargo clippy -p attestation-agent --no-default-features --features openssl,rust-crypto,cca-attester,kbs,coco_as,bin,grpc,ttrpc -- -D warnings
	cargo clippy -p attester --all-targets --no-default-features --features cca-attester,bin -- -D warnings
	cargo clippy -p coco_keyprovider --all-targets -- -D warnings
	cargo clippy -p kbc --all-targets --no-default-features --features cc_kbc,cca-attester,rust-crypto -- -D warnings
	cargo clippy -p kbs_protocol --all-targets --no-default-features \
		--features background_check,passport,rust-crypto,cca-attester,bin,aa_ttrpc -- -D warnings
	cargo clippy -p crypto --all-targets --features rust-crypto -- -D warnings
	cargo clippy -p resource_uri --all-targets -- -D warnings
	cargo clippy -p sev --all-targets -- -D warnings

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)/$(BIN_NAME)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x/ppc64le)] [OPENSSL=1] [ATTESTER=all-attesters]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
