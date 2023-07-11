#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail

parameters="KBC=offline_fs_kbc"

[ -n "${BASH_VERSION:-}" ] && set -o errtrace
[ -n "${DEBUG:-}" ] && set -o xtrace
[ -n "${TTRPC:-}" ] && parameters+=" ttrpc=true"
source $HOME/.cargo/env

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AA_DIR=$SCRIPT_DIR/../../attestation-agent

pushd $AA_DIR

make $parameters
make DESTDIR="$SCRIPT_DIR" install
popd
