PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local

REDHATOS := $(shell cat /etc/redhat-release 2> /dev/null)
DEBIANOS := $(shell cat /etc/debian_version 2> /dev/null)

TARGET_DIR := ./target
BIN_NAME := attestation-agent

DEBUG ?=
LIBC ?=
KBC ?=
DESTDIR ?= $(PREFIX)/bin

ifdef KBC
    feature := --no-default-features --features
endif

ifeq ($(LIBC), musl)
    MUSL_ADD := $(shell rustup target add x86_64-unknown-linux-musl)
    ifneq ($(DEBIANOS),)
        MUSL_INSTALL := $(shell sudo apt-get install -y musl-tools) 
    endif
    LIBC_FLAG := --target x86_64-unknown-linux-musl
    TARGET_DIR := $(TARGET_DIR)/x86_64-unknown-linux-musl
endif

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
    RATS_TLS := $(shell ls /usr/local/lib/rats-tls/ 2> /dev/null)
    ifeq ($(RATS_TLS),)
        RATS_TLS_DOWNLOAD := $(shell cd .. && rm -rf inclavare-containers && git clone https://github.com/alibaba/inclavare-containers)
        RATS_TLS_INSTALL := $(shell cd ../inclavare-containers/rats-tls && cmake -DBUILD_SAMPLES=on -H. -Bbuild && make -C build install >&2)
    endif
    RUST_FLAGS := RUSTFLAGS="-C link-args=-Wl,-rpath,/usr/local/lib/rats-tls"
endif

build:
	$(RUST_FLAGS) cargo build $(release) $(feature) $(KBC) $(LIBC_FLAG)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help============================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [KBC=xxx_kbc]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
