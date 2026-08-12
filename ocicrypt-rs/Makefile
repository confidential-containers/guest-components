# ocicrypt-rs exercises several optional keywrap / cipher backends separately.

.PHONY: lint build test

lint:
	cargo clippy -p ocicrypt-rs --all-targets --all-features -- -D warnings

build:
	cargo build -p ocicrypt-rs --all-features
	cargo build -p ocicrypt-rs --no-default-features
	cargo build -p ocicrypt-rs --no-default-features --features=block-cipher-openssl
	cargo build -p ocicrypt-rs --no-default-features --features=block-cipher-ring
	cargo build -p ocicrypt-rs --no-default-features --features=keywrap-jwe
	cargo build -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider

test: build
	cargo test -p ocicrypt-rs --all-features
	cargo test -p ocicrypt-rs --no-default-features
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-jwe
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-cmd
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-grpc
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-ttrpc
	cargo test -p ocicrypt-rs --no-default-features --features=keywrap-keyprovider-native
