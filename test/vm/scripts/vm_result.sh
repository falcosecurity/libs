#!/bin/bash

if [[ $# -ne 2 || "${EUID}" -eq 0 ]]; then
  echo "Usage: vm_result.sh BASE_DIR PYTHON_CONTAINER"
  echo "Run as non-root user on host"
  exit 1
fi

BASE_DIR="${1}";
PYTHON_CONTAINER="${2}";

set -eou pipefail

printf "\n\n[STATUS] Generate result table\n\n"

# Plot result [compiled]
docker run -v "${BASE_DIR}":/vm:z \
${PYTHON_CONTAINER} 'python3 /vm/scripts/plot_matrix.py --driver-artifacts-dir=/vm/build/driver \
--title="Driver (clang -> bpf, gcc -> kmod) kernel compatibility matrix [compiled]" --mode=compiled > /vm/build/driver_compat_matrix_compiled.md; \
if [ -f /vm/build/driver_compat_matrix_compiled.md ]; then chown -R 1000:1000 /vm/build/driver_compat_matrix_compiled.md; fi; printf "\n\n"; \
cat /vm/build/driver_compat_matrix_compiled.md';

# Plot result [compiled + success]
docker run -v "${BASE_DIR}":/vm:z \
${PYTHON_CONTAINER} 'python3 /vm/scripts/plot_matrix.py --driver-artifacts-dir=/vm/build/driver_ok \
--title="Driver (clang -> bpf, gcc -> kmod) kernel compatibility matrix [compiled + success]" --mode=success > /vm/build/driver_compat_matrix_success.md; \
if [ -f /vm/build/driver_compat_matrix_success.md ]; then chown -R 1000:1000 /vm/build/driver_compat_matrix_success.md; fi; printf "\n\n";\
cat /vm/build/driver_compat_matrix_success.md';
