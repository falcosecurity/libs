#!/bin/bash

set -e

if [[ $# -ne 2 || "${EUID}" -eq 0 ]]; then
  echo "Usage: vm_result.sh BASE_DIR PYTHON_CONTAINER"
  echo "Run as non-root user"
  exit 1
fi

BASE_DIR="${1}";
PYTHON_CONTAINER="${2}";

set -eou pipefail

echo "Generate result table"

# Plot results of drivers that compiled
docker run -v ${BASE_DIR}:/vm:z \
${PYTHON_CONTAINER} 'python3 /vm/scripts/plot_matrix.py --driver-artifacts-dir=/vm/build/driver --save-png=/vm/build/driver_compat_matrix_compiled.png \
--title="Driver (clang -> bpf, gcc -> kmod) kernel compat matrix [compiled]" --hex-color="#808080"; if [ -f /vm/build/driver_compat_matrix_compiled.png ]; then chown -R 1000:1000 /vm/build/driver_compat_matrix_compiled.png; fi';

# Plot results of drivers that both compiled and worked
docker run -v ${BASE_DIR}:/vm:z \
${PYTHON_CONTAINER} 'python3 /vm/scripts/plot_matrix.py --driver-artifacts-dir=/vm/build/driver_ok --save-png=/vm/build/driver_compat_matrix_success.png \
--title="Driver (clang -> bpf, gcc -> kmod) kernel compat matrix [compiled + success]" --hex-color="#3074EC"; if [ -f /vm/build/driver_compat_matrix_success.png ]; then chown -R 1000:1000 /vm/build/driver_compat_matrix_success.png; fi';
