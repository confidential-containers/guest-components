.PHONY: lint build test test-xrss

lint:
	cargo clippy -p image-rs --all-targets --features=default -- -D warnings
	cargo clippy -p image-rs --all-targets --no-default-features --features=kata-cc,signature-simple-xrss -- -D warnings

build:
	cargo build -p image-rs --features default

test:
	cargo test -p image-rs --features default
	cargo test -p image-rs --no-default-features --features=kata-cc,keywrap-jwe

# XRSS registry tests need credentials; keep as an explicit target for CI.
test-xrss:
	cargo test -p image-rs --no-default-features --features=kata-cc,keywrap-jwe,signature-simple-xrss
