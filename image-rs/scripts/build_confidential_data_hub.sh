#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail

[ -n "${BASH_VERSION:-}" ] && set -o errtrace
[ -n "${DEBUG:-}" ] && set -o xtrace

source $HOME/.cargo/env

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CDH_DIR=$SCRIPT_DIR/../../confidential-data-hub

pushd $CDH_DIR

make RESOURCE_PROVIDER=none KMS_PROVIDER=none RPC="${RPC}"
make DESTDIR="${SCRIPT_DIR}/${RPC}" install

file "${SCRIPT_DIR}/${RPC}/confidential-data-hub"
popd
