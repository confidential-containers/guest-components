#!/bin/bash
#
# Copyright (c) 2022 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0
#

script_dir="$(dirname $(readlink -f $0))"
test_artifacts_dir="${script_dir}/../test_data/simple-signing-scheme"
rootfs_quay_verification_directory="/etc/containers/quay_verification"

if [ $1 == "install" ]; then
    mkdir -p "${rootfs_quay_verification_directory}/signatures"

    tar -zvxf "${test_artifacts_dir}/signatures.tar" -C "${rootfs_quay_verification_directory}/signatures"

elif [ $1 == "clean" ]; then
    rm -rf "${rootfs_quay_verification_directory}/signatures"

else
    echo "Wrong or missing argument"

fi

