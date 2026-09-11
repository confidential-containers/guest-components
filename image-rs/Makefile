ARCH=$(shell uname -m)

.PHONY: lint build test

lint:
	cargo clippy -p image-rs --all-targets --features=default -- -D warnings
	cargo clippy -p image-rs --all-targets --no-default-features --features=kata-cc-rustls-tls -- -D warnings
	cargo clippy -p image-rs --all-targets --no-default-features --features=kata-cc-native-tls -- -D warnings

build:
	cargo build -p image-rs --features default

test:
	cargo test -p image-rs --features default
	cargo test -p image-rs --no-default-features --features=encryption-ring,keywrap-grpc,signature-cosign-rustls,signature-simple,kbs,oci-client/rustls-tls,keywrap-jwe
	cargo test -p image-rs --no-default-features --features=encryption-openssl,keywrap-grpc,signature-cosign-native,signature-simple,kbs,oci-client/native-tls,keywrap-jwe
	cargo test -p image-rs --no-default-features --features=kata-cc-rustls-tls,keywrap-jwe
	cargo test -p image-rs --no-default-features --features=kata-cc-native-tls,keywrap-jwe,signature-simple-xrss
