ARCH=$(shell uname -m)

.PHONY: lint build test

# keywrap-keyprovider-native pulls kbc/sgx-attester; only compile it on x86_64.
lint:
ifeq ($(ARCH),x86_64)
	cargo clippy -p ocicrypt-rs --all-targets --all-features -- -D warnings
else
	cargo clippy -p ocicrypt-rs --all-targets \
		--features async-io,block-cipher-ring,keywrap-keyprovider-grpc,keywrap-keyprovider-ttrpc \
		-- -D warnings
endif

build:
ifeq ($(ARCH),x86_64)
	cargo build -p ocicrypt-rs --all-features
endif
	cargo build -p ocicrypt-rs --no-default-features
	cargo build -p ocicrypt-rs --no-default-features --features=block-cipher-openssl
	cargo build -p ocicrypt-rs --no-default-features --features=block-cipher-ring
	cargo build -p ocicrypt-rs --no-default-features --features=keywrap-jwe
	cargo build -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider

test: build
ifeq ($(ARCH),x86_64)
	cargo test -p ocicrypt-rs --all-features
endif
	cargo test -p ocicrypt-rs --no-default-features
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-jwe
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-cmd
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-grpc
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-ttrpc
ifeq ($(ARCH),x86_64)
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-native
endif
