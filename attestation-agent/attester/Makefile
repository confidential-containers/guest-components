ARCH ?= $(shell uname -m)
LIBC ?= gnu
ATTESTER ?=
DEBUG ?=

TARGET_DIR := ../../target/$(ARCH)-unknown-linux-$(LIBC)
BIN_NAME := initdata-validator

features := bin
ifdef ATTESTER
ifneq ($(ATTESTER), none)
features += ,$(ATTESTER)
endif
else
features += ,all-attesters
endif

ifdef DEBUG
release :=
else
release := --release
endif

build:
	@echo build $(BIN_NAME)
	cargo build $(release) --no-default-features --features "$(features)" --bin $(BIN_NAME) --target $(ARCH)-unknown-linux-$(LIBC)