#!/bin/bash
# Copyright (c) 2026 NVIDIA Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="${SCRIPT_DIR}/../test_data/conformance-images"

usage() {
    cat <<EOF
Usage: $(basename "$0") <image-ref> <local-name>

Download a container image and save it as an OCI tar archive for conformance testing.

Arguments:
    image-ref   Full image reference (e.g., docker.io/library/busybox:latest)
    local-name  Name for the local tar file (without .tar extension)

The image will be saved to: test_data/conformance-images/<local-name>.tar
EOF
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
fi

IMAGE_REF="$1"
LOCAL_NAME="$2"
OUTPUT_FILE="${CONFORMANCE_DIR}/${LOCAL_NAME}.tar"

if ! command -v skopeo &> /dev/null; then
    echo "Error: skopeo is not installed" >&2
    exit 1
fi

if [[ -f "$OUTPUT_FILE" ]]; then
    echo "Warning: ${OUTPUT_FILE} already exists, overwriting..."
fi

echo "Downloading ${IMAGE_REF} to ${OUTPUT_FILE}..."
skopeo copy "docker://${IMAGE_REF}" "oci-archive:${OUTPUT_FILE}"

echo "Done. Image saved to: ${OUTPUT_FILE}"
echo "Size: $(du -h "${OUTPUT_FILE}" | cut -f1)"
