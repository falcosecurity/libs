#!/bin/bash

set -e

if [[ $# -ne 2 || "${EUID}" -eq 0 ]]; then
	echo "Usage: all_driver_sanity_test_result.sh BASE_DIR PYTHON_CONTAINER"
  echo "Run as non-root user"
  exit 1
fi

BASE_DIR="${1}";
PYTHON_CONTAINER="${2}";

set -eou pipefail

echo "Generate results table"
docker run -v ${BASE_DIR}:/driver-sanity:z \
${PYTHON_CONTAINER} 'python3 /driver-sanity/scripts/kernel_plot_compat_matrix.py --driver_artifacts_dir=/driver-sanity/build/driver-ok --save_png=/driver-sanity/build/driver_compat_matrix.png \
--title="Falco (clang -> bpf) and (gcc -> kmod) driver kernel compat matrix"; chown -R 1000:1000 /driver-sanity/build/driver_compat_matrix.png;';
