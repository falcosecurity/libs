#!/bin/bash

set -e

if [[ $# -ne 4 || "${EUID}" -eq 0 ]]; then
	echo "Usage: all_driver_sanity_test_run.sh BASE_DIR VM_PROVIDER VM_NAMES PYTHON_CONTAINER"
  echo "Run as non-root user"
  exit 1
fi

BASE_DIR="${1}";
VM_PROVIDER="${2}";
VM_NAMES="${3}";
PYTHON_CONTAINER="${4}";

readonly LIBS_DIR="${BASE_DIR}/../../..";

echo "Package up libs source for builds in containers, save to build/libs-src.tar.gz";
rm -rf /tmp/libs-src; 
cp -r ${LIBS_DIR} /tmp/libs-src; rm -rf /tmp/libs-src/build; rm -rf /tmp/libs-src/test/driver_sanity/kernel_compat/build;
LIBS_TAR_GZ="${BASE_DIR}/build/libs-src.tar.gz";
rm -f ${LIBS_TAR_GZ};
tar -czvf ${LIBS_TAR_GZ} -C /tmp/libs-src .

echo "Build scap-open userspace binary that loads the driver, uses build/libs-src.tar.gz as libs src";
docker run -v ${BASE_DIR}:/driver-sanity:z -v ${LIBS_DIR}:/falco-libs:z \
falcosecurity/falco-builder:latest bash -c '/bin/bash /driver-sanity/scripts/compile_scap_open.sh';

echo "Compile all drivers (kmod and bpf, not modern_bpf) for each compiler version, uses build/libs-src.tar.gz as libs src";
rm -rf ${BASE_DIR}/build/driver || true;
rm -rf ${BASE_DIR}/build/driver-ok || true;
GO111MODULE=off BASE_DIR=${BASE_DIR} bash -c 'go get golang.org/x/sync/semaphore; \
go run ${BASE_DIR}/scripts/main.go -compilerVersionsClang=7,9,12,14 -compilerVersionsGcc=8,9,11,12 \
-dirExtractedKernelHeaders=${BASE_DIR}/build/headers_extracted/ -dir=${BASE_DIR}'

echo "Run unit test loops for each VM"
for host in $(echo ${VM_NAMES})
do
    bash ${BASE_DIR}/scripts/vagrant_loop.sh ${BASE_DIR} ${VM_PROVIDER} ${host} || bash ${BASE_DIR}/scripts/vagrant_loop.sh ${BASE_DIR} ${VM_PROVIDER} ${host};
    sleep 1;
done

echo "Generate results table"
docker run -v ${BASE_DIR}:/driver-sanity:z \
${PYTHON_CONTAINER} 'python3 /driver-sanity/scripts/kernel_plot_compat_matrix.py --driver_artifacts_dir=/driver-sanity/build/driver-ok --save_png=/driver-sanity/build/driver_compat_matrix.png \
--title="Falco (clang - bpf) and (gcc - kmod) driver kernel compat matrix"; chown -R 1000:1000 /driver-sanity/build/driver_compat_matrix.png;';
