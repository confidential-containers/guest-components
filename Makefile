TEE_PLATFORM ?= fs
ARCH ?= $(shell uname -m)
SOURCE_ARCH := $(shell uname -m)

DESTDIR ?= /usr/local/bin

LIBC ?= musl

ATTESTER ?=

NO_RESOURCE_PROVIDER ?=

ifeq ($(NO_RESOURCE_PROVIDER), true)
  RESOURCE_PROVIDER :=
else
  RESOURCE_PROVIDER ?= kbs
endif

ifeq ($(TEE_PLATFORM), none)
  ATTESTER = none
else ifeq ($(TEE_PLATFORM), fs)
  ATTESTER = none
else ifeq ($(TEE_PLATFORM), tdx)
  ATTESTER = tdx-attester
else ifeq ($(TEE_PLATFORM), az-cvm-vtpm)
  ATTESTER = az-snp-vtpm-attester,az-tdx-vtpm-attester
else ifeq ($(TEE_PLATFORM), sev)
  ATTESTER = none
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev
  endif
else ifeq ($(TEE_PLATFORM), snp)
  ATTESTER = snp-attester
else ifeq ($(TEE_PLATFORM), se)
  ATTESTER = se-attester
else ifeq ($(TEE_PLATFORM), all)
  ATTESTER = all-attesters
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev,kbs
  endif
else ifeq ($(TEE_PLATFORM), amd)
  ATTESTER = snp-attester
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev,kbs
  endif
else ifeq ($(TEE_PLATFORM), cca)
  ATTESTER = cca-attester
endif
# TODO: Add support for CSV

ifeq ($(shell test -e /etc/debian_version && echo -n yes),yes)
    DEBIANOS = true
else
    DEBIANOS = false
endif

$(info DEBIANOS is: $(DEBIANOS))

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  $(info s390x/powerpc64le only supports gnu)
  LIBC = gnu
endif

CDH := confidential-data-hub
AA := attestation-agent
ASR := api-server-rest

BUILD_DIR := target/$(ARCH)-unknown-linux-$(LIBC)/release

CDH_BINARY := $(BUILD_DIR)/$(CDH)
AA_BINARY := $(BUILD_DIR)/$(AA)
ASR_BINARY := $(BUILD_DIR)/$(ASR)

build: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	@echo guest components built for $(TEE_PLATFORM) succeeded!

$(CDH_BINARY):
	@echo build $(CDH) for $(TEE_PLATFORM)
	cd $(CDH) && $(MAKE) RESOURCE_PROVIDER=$(RESOURCE_PROVIDER) LIBC=$(LIBC)

$(AA_BINARY):
	@echo build $(AA) for $(TEE_PLATFORM)
	cd $(AA) && $(MAKE) ttrpc=true ARCH=$(ARCH) LIBC=$(LIBC) ATTESTER=$(ATTESTER)

$(ASR_BINARY):
	@echo build $(ASR) for $(TEE_PLATFORM)
	cd $(ASR) && $(MAKE) ARCH=$(ARCH) LIBC=$(LIBC)

install: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	install -D -m0755 $(CDH_BINARY) $(DESTDIR)/$(CDH)
	install -D -m0755 $(AA_BINARY) $(DESTDIR)/$(AA)
	install -D -m0755 $(ASR_BINARY) $(DESTDIR)/$(ASR)

build-protos:
	@if [ "$(DEBIANOS)" = "true" ]; then \
	  if ! command -v protoc >/dev/null 2>&1; then \
	    echo "Installing protoc..."; \
	    sudo apt-get update && sudo apt-get install -y protobuf-compiler; \
	  else \
	    echo "protoc already installed"; \
	  fi; \
	else \
	  echo "Not Debian OS, skip"; \
  fi;
	cargo build -p protos --features build

clean:
	rm -rf target
