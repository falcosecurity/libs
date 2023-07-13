#!/bin/bash

if [[ $# -ne 2 ]]; then
  echo "Usage: bash vm_cleanup.sh BASE_DIR VM_PROVIDER"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";

set -eou pipefail

export VAGRANT_CWD="${BASE_DIR}/vm_provider/${VM_PROVIDER}"; 
vagrant destroy -f || true

rm -rf "${BASE_DIR}/build";
