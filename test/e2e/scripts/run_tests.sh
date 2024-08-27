#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_DIR="${SCRIPT_DIR}/../../../build"
E2E_DIR="${SCRIPT_DIR}/.."

export SINSP_EXAMPLE_PATH=${BUILD_DIR}/libsinsp/examples/sinsp-example
export KERNEL_MODULE=${BUILD_DIR}/driver/scap.ko
export BPF_PROBE=${BUILD_DIR}/driver/bpf/probe.o

if [[ -z "${CI+x}" ]];then
    E2E_REPORT="${BUILD_DIR}"
else
    E2E_REPORT="/tmp"
fi

args="$*"
if (($#==0)); then
    args="${E2E_DIR}/tests/"
fi

pytest --html="${E2E_REPORT}/report/report.html" ${args}
