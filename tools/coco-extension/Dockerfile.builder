# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Build environment for the CoCo guest extension payload, used by
# assemble-rootfs.sh.
#
# The extension ships no libc of its own, so the gnu-linked binaries and the
# bundled cryptsetup must be produced against the same Ubuntu release as the
# guest rootfs they are mounted into. UBUNTU_VERSION selects that release, so
# one recipe covers every variant we publish. Mirrors kata-containers'
# coco-guest-components static-build Dockerfile.
ARG UBUNTU_VERSION=26.04
FROM ubuntu:${UBUNTU_VERSION}

ARG UBUNTU_VERSION
ARG RUST_TOOLCHAIN
ARG UMOCI_VERSION=v0.6.0
ARG TARGETARCH
ARG CUDA_KEYRING_VERSION=1.1-1

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:${PATH}"
ENV LIBC=gnu

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		binutils \
		ca-certificates \
		clang \
		cryptsetup-bin \
		curl \
		g++ \
		gcc \
		libclang-dev \
		libdevmapper-dev \
		libssl-dev \
		libtss2-dev \
		make \
		musl-tools \
		openssl \
		perl \
		pkg-config \
		protobuf-compiler \
		skopeo && \
	apt-get clean && rm -rf /var/lib/apt/lists/* && \
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
		sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}" && \
	curl -fsSL -o /usr/local/bin/umoci \
		"https://github.com/opencontainers/umoci/releases/download/${UMOCI_VERSION}/umoci.linux.${TARGETARCH}" && \
	chmod +x /usr/local/bin/umoci

# NVAT_VERSION: libnvat/libnvat-dev version; keep in sync with install-nvat-sdk/action.yml.
ARG NVAT_VERSION
RUN if [ "$(uname -m)" = "x86_64" ] && [ -n "${NVAT_VERSION}" ]; then \
	case "${UBUNTU_VERSION}" in \
		24.04) nv_repo=ubuntu2404 ;; \
		26.04) nv_repo=ubuntu2604 ;; \
		*) echo "no NVIDIA apt repository known for Ubuntu ${UBUNTU_VERSION}" >&2; exit 1 ;; \
	esac && \
	tmpdir="$(mktemp -d)" && \
	curl -fsSL -o "${tmpdir}/cuda-keyring.deb" \
		"https://developer.download.nvidia.com/compute/cuda/repos/${nv_repo}/x86_64/cuda-keyring_${CUDA_KEYRING_VERSION}_all.deb" && \
	dpkg -i "${tmpdir}/cuda-keyring.deb" && \
	rm -rf "${tmpdir}" && \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		"libnvat=${NVAT_VERSION}*" \
		"libnvat-dev=${NVAT_VERSION}*" && \
	apt-get clean && rm -rf /var/lib/apt/lists/*; \
	fi

RUN ARCH="$(uname -m)"; \
	rust_arch=""; \
	case "${ARCH}" in \
		aarch64|x86_64|s390x) rust_arch="${ARCH}" ;; \
		ppc64le) rust_arch="powerpc64le" ;; \
		*) echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;; \
	esac; \
	rustup target add "${rust_arch}-unknown-linux-${LIBC}"

# assemble-rootfs.sh runs as the invoking uid so the build artefacts stay
# writable on the host bind mount; that uid still needs the toolchain.
RUN chmod -R a+rwX "${RUSTUP_HOME}" "${CARGO_HOME}"
