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

ARG RUST_TOOLCHAIN
ARG UMOCI_VERSION=v0.6.0
ARG TARGETARCH

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
		cmake \
		cryptsetup-bin \
		curl \
		g++ \
		gcc \
		git \
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

# nv-attestation-sdk-sys looks for the C header at /usr/include/nvat.h, but
# cmake installs it under /usr/local/include, hence the symlink below.
ARG NVAT_VERSION
RUN if [ "$(uname -m)" = "x86_64" ] && [ -n "${NVAT_VERSION}" ]; then \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		build-essential \
		libcurl4-openssl-dev \
		libxml2-dev \
		libxmlsec1-dev \
		zlib1g-dev && \
	tmpdir="$(mktemp -d)" && \
	git clone https://github.com/NVIDIA/attestation-sdk "${tmpdir}/attestation-sdk" && \
	git -C "${tmpdir}/attestation-sdk" fetch --depth=1 origin "${NVAT_VERSION}" && \
	git -C "${tmpdir}/attestation-sdk" checkout FETCH_HEAD && \
	cmake -S "${tmpdir}/attestation-sdk/nv-attestation-sdk-cpp" \
		-B "${tmpdir}/attestation-sdk/nv-attestation-sdk-cpp/build" \
		-DCMAKE_BUILD_TYPE=Release && \
	cmake --build "${tmpdir}/attestation-sdk/nv-attestation-sdk-cpp/build" --parallel "$(nproc)" && \
	cmake --install "${tmpdir}/attestation-sdk/nv-attestation-sdk-cpp/build" && \
	mkdir -p /usr/include && \
	ln -sf /usr/local/include/nvat.h /usr/include/nvat.h && \
	ldconfig && \
	rm -rf "${tmpdir}" && \
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
