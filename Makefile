PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin

REDHATOS := $(shell cat /etc/redhat-release 2> /dev/null)
DEBIANOS := $(shell cat /etc/debian_version 2> /dev/null)

TARGET_DIR := ./target
BIN_NAME := attestation-agent

DEBUG ?=
MUSL ?=
KBC ?=

ifdef KBC
    feature := --no-default-features --features
endif

ifdef MUSL
    MUSL_ADD := $(shell rustup target add x86_64-unknown-linux-musl)
ifneq ($(DEBIANOS),)
    MUSL_INSTALL := $(shell sudo apt install musl-tools) 
endif
    MUSL_FLAG := --target x86_64-unknown-linux-musl
    TARGET_DIR := $(TARGET_DIR)/x86_64-unknown-linux-musl
endif

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

all:
	@echo $(MUSL_ADD) $(MUSL_INSTALL)
	$(RUST_FLAGS) cargo build $(release) $(feature) $(KBC) $(MUSL_FLAG)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(BIN_NAME)
 
clean:
	cargo clean && rm -f Cargo.lock

help:
	@echo "build: make [DEBUG=1] [MUSL=1] [KBC=xxx_kbc]"
	@echo "KBC supported:"
	@echo "    sample_kbc"
	@echo "    offline_fs_kbc"