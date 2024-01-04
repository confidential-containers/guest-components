#!/bin/bash
#
# Copyright (c) 2022 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

[ -n "${DEBUG:-}" ] && set -o xtrace

script_dir=$(dirname $(readlink -f $0))
test_resource_json_name="${2:-aa-offline_fs_kbc-resources.json}"
resource_json_name="aa-offline_fs_kbc-resources.json"
keys_json_name="aa-offline_fs_kbc-keys.json"
test_resource_record="${script_dir}/../test_data/offline-fs-kbc/${test_resource_json_name}"
test_keys="${script_dir}/../test_data/offline-fs-kbc/${keys_json_name}"
target_resource_record_path="/etc/${resource_json_name}"
target_keys_path="/etc/${keys_json_name}"

if [ "${1:-}" = "install" ]; then
    sudo install --owner=root --group=root --mode=0640 "${test_resource_record}" "${target_resource_record_path}"
    sudo install --owner=root --group=root --mode=0640 "${test_keys}" "${target_keys_path}"

    # This is a workaround for CDH to read the aa_kbc_params from a
    # file rather than kernel commandline. This makes a fake environment
    # that CDH will recognize as it is in "peer pod", so aa_kbc param will
    # be read from a file.
    # TODO: when CDH has its own configuration launch file, we can
    # promote this way.
    mkdir -p /run/peerpod
    touch /run/peerpod/daemon.json
    echo "aa_kbc_params = \"offline_fs_kbc::null\"" > /etc/agent-config.toml
elif [ "${1:-}" = "clean" ]; then
    sudo rm "${target_resource_record_path}"
    sudo rm "${target_keys_path}"

else
    echo >&2 "ERROR: Wrong or missing argument: '${1:-}'"
fi
