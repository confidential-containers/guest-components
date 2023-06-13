#!/bin/bash

set -euo pipefail

bold_echo() {
  echo -e "\033[1m${1}\033[0m"
}

start_aa() {
	bold_echo "Build attestation-agent..."
	cargo b --release -p attestation-agent \
		--no-default-features \
		--features grpc,cc_kbc,openssl

	bold_echo "Start attestation-agent..."
	AA_SAMPLE_ATTESTER_TEST=1 ./target/release/attestation-agent \
		--keyprovider_sock 127.0.0.1:50000 --getresource_sock 127.0.0.1:50001 &
	aa_pid=$!
	wait-for-it 127.0.0.1:50000 --timeout=10
}
