TEE_PLATFORM ?= fs
ARCH ?= $(shell uname -m)

DESTDIR ?= /usr/local/bin

LIBC ?= musl
KBC ?=
RESOURCE_PROVIDER ?= kbs

ifeq ($(TEE_PLATFORM), none)
  KBC = cc_kbc
else ifeq ($(TEE_PLATFORM), fs)
  KBC = offline_fs_kbc
else ifeq ($(TEE_PLATFORM), tdx)
  LIBC = gnu
  KBC = cc_kbc_tdx
else ifeq ($(TEE_PLATFORM), az-tdx-vtpm)
  KBC = cc_kbc_az_tdx_vtpm
else ifeq ($(TEE_PLATFORM), sev)
  KBC = online_sev_kbc
  RESOURCE_PROVIDER = sev
else ifeq ($(TEE_PLATFORM), snp)
  KBC = cc_kbc_snp
else ifeq ($(TEE_PLATFORM), az-snp-vtpm)
  KBC = cc_kbc_az_snp_vtpm
endif
# TODO: Add support for CCA and CSV

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
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
	cd $(AA) && $(MAKE) ttrpc=true ARCH=$(ARCH) LIBC=$(LIBC) KBC=$(KBC)

$(ASR_BINARY):
	@echo build $(ASR) for $(TEE_PLATFORM)
	cd $(ASR) && $(MAKE) ARCH=$(ARCH) LIBC=$(LIBC)

install: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	install -D -m0755 $(CDH_BINARY) $(DESTDIR)/$(CDH)
	install -D -m0755 $(AA_BINARY) $(DESTDIR)/$(AA)
	install -D -m0755 $(ASR_BINARY) $(DESTDIR)/$(ASR)

clean:
	rm -rf target
