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
KBC ?=
ttrpc ?=
grpc ?=
DESTDIR ?= $(PREFIX)/bin
RUSTFLAGS_ARGS ?=
features ?=
OPENSSL ?=

ifeq ($(SOURCE_ARCH), ppc64le)
  ARCH=powerpc64le
endif

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  OPENSSL=1
endif

ifdef KBC
    features += $(KBC)
else
    features += sample_kbc
endif

ifeq ($(ttrpc), true)
    features += ttrpc
else
    features += grpc
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

ifeq ($(KBC), eaa_kbc)
    ifeq ($(LIBC), musl)
        $(error ERROR: EAA KBC does not support MUSL build!)
    endif
    ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
        $(error ERROR: EAA KBC does not support s390x and ppc64le architectures!)
    endif
    RATS_TLS := $(shell ls /usr/local/lib/rats-tls/ 2> /dev/null)
    ifeq ($(RATS_TLS),)
        RATS_TLS_DOWNLOAD := $(shell cd .. && rm -rf inclavare-containers && git clone https://github.com/alibaba/inclavare-containers)
        RATS_TLS_INSTALL := $(shell cd ../inclavare-containers/rats-tls && cmake -DBUILD_SAMPLES=on -H. -Bbuild && make -C build install >&2)
    endif
    RUSTFLAGS_ARGS += -C link-args=-Wl,-rpath,/usr/local/lib/rats-tls
endif

ifeq ($(KBC), offline_sev_kbc)
    ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
        $(error ERROR: Offline SEV KBC does not support s390x and ppc64le architectures!)
    endif
endif

ifneq ($(RUSTFLAGS_ARGS),)
    RUST_FLAGS := RUSTFLAGS="$(RUSTFLAGS_ARGS)"
endif

ifdef OPENSSL
    features := $(features),openssl
else
    features := $(features),rust-crypto
endif

build:
	cd app && $(RUST_FLAGS) cargo build $(release) --no-default-features --features "$(features)" $(LIBC_FLAG)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

install: 
	install -D -m0755 $(TARGET) $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/$(BIN_NAME)

clean:
	cargo clean

help:
	@echo "==========================Help========================================="
	@echo "build: make [DEBUG=1] [LIBC=(musl)] [ARCH=(x86_64/s390x/ppc64le)] [KBC=xxx_kbc] [OPENSSL=1]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(musl)]"
