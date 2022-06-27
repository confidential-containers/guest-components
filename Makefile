PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local

REDHATOS := $(shell cat /etc/redhat-release 2> /dev/null)
DEBIANOS := $(shell cat /etc/debian_version 2> /dev/null)

TARGET_DIR := target
BIN_NAME := attestation-agent

SOURCE_ARCH := $(shell uname -m)

ARCH ?= $(shell uname -m)
DEBUG ?=
LIBC ?= gnu
KBC ?=
DESTDIR ?= $(PREFIX)/bin
RUSTFLAGS_ARGS ?=

ifdef KBC
    feature := --no-default-features --features
endif

ifeq ($(ARCH), s390x)
    $(error ERROR: Attestation agent does not support building for the musl libc target for s390x architecture)
endif

ifeq ($(LIBC), musl)
    MUSL_ADD := $(shell rustup target add ${ARCH}-unknown-linux-musl)
    ifneq ($(DEBIANOS),)
        MUSL_INSTALL := $(shell sudo apt-get install -y musl-tools) 
    endif
endif

ifneq ($(SOURCE_ARCH), $(ARCH))
    ifneq ($(DEBIANOS),)
        GCC_COMPILER_FOR_TARGET_ARCH := gcc-$(ARCH)-linux-$(LIBC)
        GCC_FOR_TARGET_ARCH_INSTALL := $(shell sudo apt-get install -y ${GCC_COMPILER_FOR_TARGET_ARCH})
        RUST_TARGET_FOR_TARGET_ARCH_INSTALL := $(shell rustup target add ${ARCH}-unknown-linux-${LIBC})
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

ifneq ($(RUSTFLAGS_ARGS),)
    RUST_FLAGS := RUSTFLAGS="$(RUSTFLAGS_ARGS)"
endif

build:
	cd app && $(RUST_FLAGS) cargo build $(release) $(feature) $(KBC) $(LIBC_FLAG)

TARGET := app/$(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x)] [KBC=xxx_kbc]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
