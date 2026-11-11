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
#
# UBUNTU_DIGEST is the multi-arch index digest of ubuntu:${UBUNTU_VERSION} and
# must be overridden together with UBUNTU_VERSION.
ARG UBUNTU_VERSION=26.04
ARG UBUNTU_DIGEST=6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c
FROM ubuntu:${UBUNTU_VERSION}@sha256:${UBUNTU_DIGEST}

ARG UBUNTU_VERSION
ARG RUST_TOOLCHAIN
# Bumping UMOCI_VERSION requires updating the per-arch hashes below, taken
# from the release's signed umoci.sha256sum.
ARG UMOCI_VERSION=v0.6.0
ARG TARGETARCH
ARG CUDA_KEYRING_VERSION=1.1-1

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:${PATH}"
ENV LIBC=gnu

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}/bin"

# Ubuntu 24.04's rustup (1.26) expects ${CARGO_HOME}/bin/rustup to exist when
# updating proxies, even though the archive package installs into /usr/bin.
RUN apt-get update && \
	apt-get install -y --no-install-recommends \
		binutils \
		ca-certificates \
		clang \
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
		rustup \
		skopeo && \
	apt-get clean && rm -rf /var/lib/apt/lists/* && \
	ln -s /usr/bin/rustup "${CARGO_HOME}/bin/rustup" && \
	rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --no-self-update && \
	rustup default "${RUST_TOOLCHAIN}"

RUN case "${TARGETARCH}" in \
		amd64) umoci_sha256=b51c267ec394499e42c6fde47f240b7b7dba57ea49df0b5acd304378b82a3b71 ;; \
		arm64) umoci_sha256=5cfd17f2e7a4bcf9ed67ea1b955ca893d200349b9ce6a3d3707dba415f458a1f ;; \
		s390x) umoci_sha256=abe2282c6d49a7289f381b9572a01f4d4079919a41fadaca67047a5015cc0e0a ;; \
		*) echo "no pinned umoci hash for TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
	esac && \
	tmpdir="$(mktemp -d)" && \
	curl -fsSL -o "${tmpdir}/umoci" \
		"https://github.com/opencontainers/umoci/releases/download/${UMOCI_VERSION}/umoci.linux.${TARGETARCH}" && \
	echo "${umoci_sha256}  ${tmpdir}/umoci" | sha256sum -c - && \
	install -m 0755 "${tmpdir}/umoci" /usr/local/bin/umoci && \
	rm -rf "${tmpdir}"

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
RUN find "${RUSTUP_HOME}" "${CARGO_HOME}" -not -type l -exec chmod a+rwX {} +
