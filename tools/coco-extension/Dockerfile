# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# OCI container image flavour of the CoCo guest extension.
#
# The build context MUST be the assembled extension rootfs produced by
# assemble-rootfs.sh, e.g.:
#
#   ./assemble-rootfs.sh
#   docker build \
#     -f tools/coco-extension/Dockerfile \
#     -t ghcr.io/confidential-containers/guest-components/coco-extension:dev \
#     build/coco-extension-rootfs
#
# The image is intentionally scratch-based: it carries only the extension
# payload (guest-component binaries, ocicrypt config, components.toml manifest
# and the pause bundle) with no base OS. Consumers either use the layers
# directly or convert the image into an EROFS + dm-verity extension disk image.
FROM scratch

LABEL org.opencontainers.image.title="CoCo guest extension" \
      org.opencontainers.image.description="Confidential Containers guest components packaged as a kata composable guest extension" \
      org.opencontainers.image.source="https://github.com/confidential-containers/guest-components" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY . /
