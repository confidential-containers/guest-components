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

TARGET_DIR := target
BIN_NAME := attestation-agent

SOURCE_ARCH := $(shell uname -m)

ARCH ?= $(shell uname -m)
DEBUG ?=
LIBC ?= gnu
KBC ?=
DESTDIR ?= $(PREFIX)/bin
RUSTFLAGS_ARGS ?=
OPENSSL ?=

ifdef KBC
    feature := --no-default-features --features
    FEATURES := $(KBC)
else
    feature := --features
    FEATURES := default
endif

ifeq ($(LIBC), musl)
    ifeq ($(ARCH), s390x)
        $(error ERROR: Attestation agent does not support building with the musl libc target for s390x architecture!)
    endif
    MUSL_ADD := $(shell rustup target add ${ARCH}-unknown-linux-musl)
    ifeq ($(DEBIANOS), true)
        MUSL_INSTALL := $(shell sudo apt-get install -y musl-tools) 
    endif
endif

ifneq ($(SOURCE_ARCH), $(ARCH))
    ifeq ($(DEBIANOS), true)
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

ifeq ($(SOURCE_ARCH), s390x)
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

ifeq ($(KBC), eaa_kbc)
    ifeq ($(LIBC), musl)
        $(error ERROR: EAA KBC does not support MUSL build!)
    endif
    ifeq ($(ARCH), s390x)
        $(error ERROR: EAA KBC does not support s390x architecture!)
    endif
    RATS_TLS := $(shell ls /usr/local/lib/rats-tls/ 2> /dev/null)
    ifeq ($(RATS_TLS),)
        RATS_TLS_DOWNLOAD := $(shell cd .. && rm -rf inclavare-containers && git clone https://github.com/alibaba/inclavare-containers)
        RATS_TLS_INSTALL := $(shell cd ../inclavare-containers/rats-tls && cmake -DBUILD_SAMPLES=on -H. -Bbuild && make -C build install >&2)
    endif
    RUSTFLAGS_ARGS += -C link-args=-Wl,-rpath,/usr/local/lib/rats-tls
endif

ifeq ($(KBC), offline_sev_kbc)
    ifeq ($(ARCH), s390x)
        $(error ERROR: Offline SEV KBC does not support s390x architecture!)
    endif
endif

ifneq ($(RUSTFLAGS_ARGS),)
    RUST_FLAGS := RUSTFLAGS="$(RUSTFLAGS_ARGS)"
endif

ifdef OPENSSL
    FEATURES := $(FEATURES),openssl
else
    FEATURES := $(FEATURES),rust-crypto
endif

build:
	cd app && $(RUST_FLAGS) cargo build $(release) $(feature) $(FEATURES) $(LIBC_FLAG)

TARGET := app/$(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x)] [KBC=xxx_kbc] [OPENSSL=1]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
