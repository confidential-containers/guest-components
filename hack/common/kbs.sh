#!/bin/bash

set -euo pipefail

bold_echo() {
  echo -e "\033[1m${1}\033[0m"
}

start_kbs() {
	bold_echo "Build kbs..."
	pushd kbs
	cargo b --release -p kbs

	bold_echo "Start kbs..."
	openssl genpkey -algorithm ed25519 > kbs.key
	openssl pkey -in kbs.key -pubout -out kbs.pem
	./target/release/kbs --socket 127.0.0.1:8080 --insecure-http --auth-public-key ./kbs.pem &
	kbs_pid=$!
	wait-for-it 127.0.0.1:8080 --timeout=10
	popd
}
