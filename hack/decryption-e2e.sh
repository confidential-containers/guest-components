#!/bin/bash

set -euo pipefail

KEYPROVIDER_SOCKET=127.0.0.1:50000
KBS_RESOURCE=default/key/image

cleanup() {
	docker ps -q --filter "name=registry" | grep -q . && docker rm -f registry
	jobs -p | grep -q . && jobs -p | xargs kill
}
trap 'cleanup' EXIT

bold_echo() {
  echo -e "\033[1m${1}\033[0m"
}

# shellcheck source=hack/common/registry.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/registry.sh"
# shellcheck source=hack/common/kbs.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/kbs.sh"
# shellcheck source=hack/common/attestation-agent.sh
. "$(dirname "${BASH_SOURCE[0]}")/common/attestation-agent.sh"

[ -d "./kbs" ] || git clone https://github.com/confidential-containers/kbs.git

bold_echo "Build coco_keyprovider..."
cargo b --release -p coco_keyprovider

bold_echo "Start coco_keyprovider..."
./target/release/coco_keyprovider --socket "$KEYPROVIDER_SOCKET" &
keyprovider_pid=$!
wait-for-it "$KEYPROVIDER_SOCKET" --timeout=10

start_tls_registry

bold_echo "Encrypt image with random secret..."
cat <<EOF > ocicrypt.conf
{
	"key-providers": {
		"attestation-agent": {
			"grpc": "$KEYPROVIDER_SOCKET"
		}
	}
}
EOF
keypath="${PWD}/image_key"
head -c 32 < /dev/urandom > "$keypath"
keyid="kbs://127.0.0.1:8080/${KBS_RESOURCE}"
OCICRYPT_KEYPROVIDER_CONFIG="${PWD}/ocicrypt.conf" skopeo copy \
	--insecure-policy \
	--encryption-key "provider:attestation-agent:keypath=${keypath}::keyid=${keyid}::algorithm=A256GCM" \
	--dest-tls-verify=false \
	docker://busybox \
	docker://localhost:5000/coco/busybox_encrypted:v1
kill "$keyprovider_pid"

start_kbs

bold_echo "Store key in kbs repository..."
mkdir -p "/opt/confidential-containers/kbs/repository/$(dirname "$KBS_RESOURCE")"
cp "$keypath" "/opt/confidential-containers/kbs/repository/${KBS_RESOURCE}"

start_aa

bold_echo "Run image decryption test..."
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test \
	-p image-rs \
	--features encryption-ring,getresource,oci-distribution/rustls-tls-native-roots,e2e-test \
	-- --test decrypt_layers_via_kbs --nocapture
