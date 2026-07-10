#!/usr/bin/env bash
#
# Copyright (c) 2026 Confidential Containers contributors
#
# SPDX-License-Identifier: Apache-2.0
#
# Assemble the CoCo guest extension rootfs.
#
# The rootfs produced here is the payload of the "coco-extension" image
# (kata-containers-coco-extension.img). It is consumed in two ways:
#
#   * packed into a "FROM scratch" OCI container image (see Dockerfile), and
#   * turned into an EROFS + dm-verity disk image (see build-erofs-image.sh).
#
# The layout mirrors what kata-containers' kata-deploy-binaries.sh
# (install_image_coco_extension) produces, so the resulting image is a drop-in
# for kata's own rootfs-image-coco-extension asset:
#
#   usr/local/bin/attestation-agent
#   usr/local/bin/confidential-data-hub
#   usr/local/bin/api-server-rest
#   usr/local/bin/attestation-agent-nv (x86_64, when NVIDIA SDK is available)
#   usr/local/lib/libnvat.so*
#   etc/ocicrypt_config.json
#   etc/kata-extensions/components.toml
#   usr/sbin/cryptsetup
#   pause_bundle/...
#
set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root_dir="$(cd "${script_dir}/../.." && pwd)"

# Target selection. Defaults match a native x86_64 build; the CI workflow
# overrides these per architecture.
ARCH="${ARCH:-$(uname -m)}"
LIBC="${LIBC:-musl}"

# Attesters and resource providers compiled into the guest components. These are
# architecture specific (e.g. tdx/snp attesters only build on x86_64, se-attester
# only on s390x), so the caller is expected to set ATTESTER accordingly.
ATTESTER="${ATTESTER:-none}"
NV_ATTESTER="${NV_ATTESTER:-${ATTESTER},nvidia-attester}"
RESOURCE_PROVIDER="${RESOURCE_PROVIDER:-kbs}"
INCLUDE_NVIDIA_ATTESTER="${INCLUDE_NVIDIA_ATTESTER:-auto}"
INCLUDE_CRYPTSETUP="${INCLUDE_CRYPTSETUP:-yes}"
NVAT_LIB_DIR="${NVAT_LIB_DIR:-/usr/local/lib}"

# TEE_PLATFORM is intentionally left empty so the top-level Makefile does not
# override the ATTESTER/RESOURCE_PROVIDER values passed in the environment. This
# mirrors kata's build-static-coco-guest-components.sh.
TEE_PLATFORM="${TEE_PLATFORM:-}"

# Pause image to bundle. Kept in sync with kata's versions.yaml (.externals.pause).
PAUSE_IMAGE_REPO="${PAUSE_IMAGE_REPO:-docker://registry.k8s.io/pause}"
PAUSE_IMAGE_VERSION="${PAUSE_IMAGE_VERSION:-3.10}"

# Where to assemble the rootfs. Must be writable and is also used as the OCI
# image build context.
ROOTFS_DIR="${ROOTFS_DIR:-${repo_root_dir}/build/coco-extension-rootfs}"

info() { echo "[assemble-rootfs] $*"; }
die() { echo "[assemble-rootfs] ERROR: $*" >&2; exit 1; }

# The top-level Makefile remaps ppc64le -> powerpc64le for the rust target
# triple; mirror that so BUILD_DIR below points at the right place.
rust_arch="${ARCH}"
[[ "${rust_arch}" == "ppc64le" ]] && rust_arch="powerpc64le"

build_dir="${repo_root_dir}/target/${rust_arch}-unknown-linux-${LIBC}/release"

build_guest_components() {
	info "Building guest components (ARCH=${ARCH} LIBC=${LIBC} ATTESTER=${ATTESTER})"

	make -C "${repo_root_dir}" build \
		TEE_PLATFORM="${TEE_PLATFORM}" \
		ARCH="${ARCH}" \
		LIBC="${LIBC}" \
		ATTESTER="${ATTESTER}" \
		RESOURCE_PROVIDER="${RESOURCE_PROVIDER}"

	# Strip to keep the extension image small; the debug info is not shippable.
	local strip_bin="strip"
	command -v "${strip_bin}" >/dev/null 2>&1 || die "strip not found"
	for bin in confidential-data-hub attestation-agent api-server-rest; do
		"${strip_bin}" "${build_dir}/${bin}"
	done
}

copy_non_glibc_library_closure() {
	local lib="$1"
	local dest_dir="${ROOTFS_DIR}/usr/local/lib"
	local dep
	local dep_path
	local dep_name

	mkdir -p "${dest_dir}"

	while read -r dep; do
		if [[ "${dep}" == *"=>"* ]]; then
			dep_path="${dep#*=> }"
			dep_path="${dep_path%% *}"
		else
			dep_path="${dep%% *}"
		fi

		[[ "${dep_path}" == /* ]] || continue
		[[ -f "${dep_path}" ]] || continue

		dep_name="$(basename "${dep_path}")"
		case "${dep_name}" in
			ld-linux-*|libc.so.*|libdl.so.*|libm.so.*|libpthread.so.*|librt.so.*)
				continue
				;;
		esac

		cp -a "${dep_path}" "${dest_dir}/"
	done < <(ldd "${lib}")
}

build_nvidia_attestation_agent() {
	case "${INCLUDE_NVIDIA_ATTESTER}" in
		yes) ;;
		no) return 0 ;;
		auto)
			if [[ "${ARCH}" != "x86_64" ]]; then
				info "Skipping NVIDIA attester variant on ${ARCH}"
				return 0
			fi
			;;
		*) die "unsupported INCLUDE_NVIDIA_ATTESTER=${INCLUDE_NVIDIA_ATTESTER}" ;;
	esac

	[[ -e "${NVAT_LIB_DIR}/libnvat.so" || -e "${NVAT_LIB_DIR}/libnvat.so.1" ]] || \
		die "NVIDIA SDK libnvat.so not found in ${NVAT_LIB_DIR}"

	info "Building NVIDIA attester variant (ATTESTER=${NV_ATTESTER})"
	rm -f "${build_dir}/attestation-agent"

	NVAT_USE_SYSTEM_LIB=1 \
		make -C "${repo_root_dir}/attestation-agent" \
		ttrpc=true \
		ARCH="${ARCH}" \
		LIBC="${LIBC}" \
		ATTESTER="${NV_ATTESTER}" \
		RUSTFLAGS_ARGS="-L ${NVAT_LIB_DIR}"

	strip "${build_dir}/attestation-agent"
	install -D -m0755 \
		"${build_dir}/attestation-agent" \
		"${ROOTFS_DIR}/usr/local/bin/attestation-agent-nv"

	info "Installing NVIDIA attestation libraries"
	mkdir -p "${ROOTFS_DIR}/usr/local/lib"
	cp -a "${NVAT_LIB_DIR}"/libnvat.so* "${ROOTFS_DIR}/usr/local/lib/"

	local libnvat
	libnvat="$(find "${NVAT_LIB_DIR}" -maxdepth 1 -name 'libnvat.so*' | sort | head -n 1)"
	if [[ -n "${libnvat}" ]]; then
		copy_non_glibc_library_closure "${libnvat}"
	fi
}

install_cryptsetup() {
	if [[ "${INCLUDE_CRYPTSETUP}" != "yes" ]]; then
		return 0
	fi

	command -v cryptsetup >/dev/null 2>&1 || die "cryptsetup not found"
	info "Installing cryptsetup"
	install -D -m0755 \
		"$(command -v cryptsetup)" \
		"${ROOTFS_DIR}/usr/sbin/cryptsetup"
}

install_guest_components() {
	info "Installing guest components into ${ROOTFS_DIR}"

	make -C "${repo_root_dir}" install \
		TEE_PLATFORM="${TEE_PLATFORM}" \
		ARCH="${ARCH}" \
		LIBC="${LIBC}" \
		DESTDIR="${ROOTFS_DIR}/usr/local/bin"

	# ocicrypt config used by CDH's keyprovider; referenced from components.toml.
	install -D -m0644 \
		"${repo_root_dir}/confidential-data-hub/hub/src/image/ocicrypt_config.json" \
		"${ROOTFS_DIR}/etc/ocicrypt_config.json"

	build_nvidia_attestation_agent
	install_cryptsetup
}

install_pause_bundle() {
	info "Pulling pause image ${PAUSE_IMAGE_REPO}:${PAUSE_IMAGE_VERSION}"
	command -v skopeo >/dev/null 2>&1 || die "skopeo not found"
	command -v umoci >/dev/null 2>&1 || die "umoci not found"

	local workdir
	workdir="$(mktemp -d)"
	# shellcheck disable=SC2064
	trap "rm -rf '${workdir}'" RETURN

	skopeo copy "${PAUSE_IMAGE_REPO}:${PAUSE_IMAGE_VERSION}" \
		"oci:${workdir}/pause:${PAUSE_IMAGE_VERSION}"

	rm -rf "${ROOTFS_DIR}/pause_bundle"
	umoci unpack --rootless \
		--image "${workdir}/pause:${PAUSE_IMAGE_VERSION}" \
		"${ROOTFS_DIR}/pause_bundle"
	rm -f "${ROOTFS_DIR}/pause_bundle/umoci.json"
}

install_manifest() {
	info "Writing extension component manifest"
	# Always ship the same manifest kata uses, including the nvidia attester
	# variant selector. attestation-agent-nv is only built on x86_64, but the
	# manifest must stay identical so kata-agent and NVRC share one contract.
	install -D -m0644 \
		"${script_dir}/components.toml" \
		"${ROOTFS_DIR}/etc/kata-extensions/components.toml"
}

main() {
	info "Assembling CoCo extension rootfs at ${ROOTFS_DIR}"
	rm -rf "${ROOTFS_DIR}"
	mkdir -p "${ROOTFS_DIR}"

	build_guest_components
	install_guest_components
	install_pause_bundle
	install_manifest

	info "Done. Rootfs contents:"
	find "${ROOTFS_DIR}" -maxdepth 5 -printf '  %P\n' | sort
}

main "$@"
