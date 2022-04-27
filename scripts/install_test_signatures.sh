#!/bin/bash
#
# Copyright (c) 2022 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0
#

image_security_dir="/run/image-security"
simple_signing_name="simple_signing"
sigstore_config_name="sigstore_config"
simple_signing_dir="${image_security_dir}/${simple_signing_name}"
sigsotre_config_dir="${simple_signing_dir}/${sigstore_config_name}"

script_dir="$(dirname $(readlink -f $0))"
test_artifacts_dir="${script_dir}/../test_data/simple-signing-scheme"
rootfs_quay_verification_directory="/etc/containers/quay_verification"

if [ $1 == "install" ]; then
    mkdir -p ${image_security_dir}
    mkdir -p ${simple_signing_dir}
    mkdir -p ${sigsotre_config_dir}
    mkdir -p "${rootfs_quay_verification_directory}/signatures"

    tar -zvxf "${test_artifacts_dir}/signatures.tar" -C "${rootfs_quay_verification_directory}/signatures"
    install -o root -g root -m 0644 "${test_artifacts_dir}/security_policy.json" "${image_security_dir}/security_policy.json"
    install -o root -g root -m 0644 "${test_artifacts_dir}/pubkey.gpg" "${simple_signing_dir}/pubkey.gpg"
    install -o root -g root -m 0644 "${test_artifacts_dir}/sigstore_config.yaml" "${sigsotre_config_dir}/sigstore_config.yaml"

elif [ $1 == "clean" ]; then
    rm -rf ${image_security_dir}
    rm -rf "${rootfs_quay_verification_directory}/signatures"

else
    echo "Wrong or missing argument"

fi

