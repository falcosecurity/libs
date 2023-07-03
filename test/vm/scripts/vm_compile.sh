#!/bin/bash

if [[ $# -ne 1 || "${EUID}" -eq 0 ]]; then
  echo "Usage: bash vm_compile.sh BASE_DIR"
  echo "Run as non-root user on host"
  exit 1
fi

BASE_DIR="${1}";

set -eou pipefail

readonly LIBS_DIR="${BASE_DIR}/../..";

printf "\n\n[STATUS] Package libs source for builds in containers, save to build/libs-src.tar.gz\n\n";

rm -rf /tmp/libs-src; 
mkdir -p /tmp/libs-src/;
# Workaround for copying to support macOS as extracted kernel headers directories under test/vm/build cause trouble
pushd ${LIBS_DIR}
cp -rv `ls | grep -v "build" | grep -v "test"` /tmp/libs-src/;
mkdir -p /tmp/libs-src/test/drivers;
cp -r test/drivers/* /tmp/libs-src/test/drivers;
mkdir -p /tmp/libs-src/test/e2e;
cp -r test/e2e/* /tmp/libs-src/test/e2e;
cp CMakeListsGtestInclude.cmake /tmp/libs-src/CMakeListsGtestInclude.cmake;
popd

LIBS_TAR_GZ="${BASE_DIR}/build/libs-src.tar.gz";
rm -f ${LIBS_TAR_GZ};
tar -czvf ${LIBS_TAR_GZ} -C /tmp/libs-src .

printf "\n\n[STATUS] Compile drivers (kmod and bpf, not modern_bpf) for each compiler version using build/libs-src.tar.gz as libs source\n\n";
rm -rf ${BASE_DIR}/build/driver || true;
rm -rf ${BASE_DIR}/build/driver_ok || true;

# You have the option to customize the args to the Go launcher script
# -compilerVersionsClang=15
# -compilerVersionsClang=7,9,10,12,14,15,16
# -compilerVersionsGcc=""
GO111MODULE=off BASE_DIR=${BASE_DIR} bash -c 'go get golang.org/x/sync/semaphore; \
go run ${BASE_DIR}/scripts/main.go -compilerVersionsClang=7,12,14,16 -compilerVersionsGcc=5,9,11,13 \
-dirExtractedKernelHeaders=${BASE_DIR}/build/headers_extracted/ -dir=${BASE_DIR}'

printf "\n\n[STATUS] Build scap-open userspace binary using build/libs-src.tar.gz as libs source\n\n";
docker run -v "${BASE_DIR}":/vm:z \
falcosecurity/falco-builder:latest bash -c '/bin/bash /vm/scripts/compile_scap_open.sh';
