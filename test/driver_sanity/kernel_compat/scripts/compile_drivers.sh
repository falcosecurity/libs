#!/bin/bash

if [[ $# -ne 5 ]]; then
	echo "Usage: bash compile_driver.sh LLC CLANG GCC KMOD BPF"
  exit 1
fi

echo "Trying to build driver artifacts for extracted kernel headers, script continues on failure ... "


DIR_EXTRACTED_KERNEL_HEADERS_SUB_DIRS="/headers"; # host dir mounted in container
DRIVER_OUT_DIR="/driver-sanity/build/driver"; # host dir mounted in container
LIBS_TAR_GZ="/driver-sanity/build/libs-src.tar.gz"; # host dir mounted in container

if [[ ! -f ${LIBS_TAR_GZ} ]]; then
	echo "Container requires libs source in libs-src.tar.gz format and mounted to /driver-sanity/build/libs-src.tar.gz in container"
  exit 1
fi

LLC="${1}"; # only needed for eBPF
CLANG="${2}"; # only needed for eBPF
GCC="${3}"; # only needed for kmod
KMOD="${4}";                    
BPF="${5}";

set -eou pipefail

LIBS_DIR="/libs";
mkdir -p "${DRIVER_OUT_DIR}";
mkdir -p "${LIBS_DIR}/build";
tar -xvf ${LIBS_TAR_GZ} -C ${LIBS_DIR}/;  # fresh extraction of libs src in container, clean build dir

pushd "${LIBS_DIR}/build";
pwd

cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF="${BPF}" -DBUILD_DRIVER="${KMOD}" -DBUILD_LIBSCAP_GVISOR=OFF -DCREATE_TEST_TARGETS=OFF ..

CLANG_VERSION=$(echo ${CLANG} | sed "s/.*\///");
GCC_VERSION=$(echo ${GCC} | sed "s/.*\///");
if [[ "${BPF}" == *"ON"* ]]; then
  OUT_BPF="${DRIVER_OUT_DIR}/${CLANG_VERSION}"; mkdir -p "${OUT_BPF}";
  chown -R 1000:1000 "${OUT_BPF}";
  if [[ ! -d "${OUT_BPF}" ]];  then
    exit 1
  fi
elif [[ "${KMOD}" == *"ON"* ]]; then
  OUT_KMOD="${DRIVER_OUT_DIR}/${GCC_VERSION}"; mkdir -p "${OUT_KMOD}";
  chown -R 1000:1000 "${OUT_KMOD}";
  if [[ ! -d "${OUT_KMOD}" ]];  then
    exit 1
  fi
fi

DIRS="${DIR_EXTRACTED_KERNEL_HEADERS_SUB_DIRS}/*"
for d in $DIRS
do

  KERNEL_UNAME_R=$(basename "${d}" | sed "s/.*devel-//" );
  echo ${KERNEL_UNAME_R}

  # RPM based extracted headers sources dir
  SOURCES="${d}/usr/src/kernels/*"
  if [[ "${d}" == *"generic" ]]; then
    # DEB ubuntu based extracted headers sources dir
    SOURCES="${d}/usr/src/*";
  fi

  if [[ "${BPF}" == *"ON"* ]]; then
    echo "Trying to build driver-bpf for ${KERNEL_UNAME_R} using ${CLANG_VERSION}...";
    "${CLANG}" --version;
    rm -f "${LIBS_DIR}/build/driver/bpf/probe.o";
    make LLC="${LLC}" CLANG="${CLANG}" \
    KERNELDIR=${SOURCES} -B -C "${LIBS_DIR}/build/driver/bpf"

    if [[ -f "${LIBS_DIR}/build/driver/bpf/probe.o" ]]; then
      cp "${LIBS_DIR}/build/driver/bpf/probe.o" "${OUT_BPF}/${KERNEL_UNAME_R}.o";
      echo "Build was successful for bpf - out artifact: ${OUT_BPF}/${KERNEL_UNAME_R}.o";
      ls -l ${OUT_BPF}/${KERNEL_UNAME_R}.o;
    fi
  elif [[ -x ${GCC} && "${KMOD}" == *"ON"* ]]; then # fail safe as system standard GCC is selected when "${GCC}" not installed
    echo "Trying to build driver-kmod for ${KERNEL_UNAME_R} using ${GCC_VERSION}...";
    "${GCC}" --version;
    rm -f "${LIBS_DIR}/build/driver/scape.ko";
    make GCC="${GCC}" \
    KERNELDIR=${SOURCES} -B -C "${LIBS_DIR}/build/driver/"

    if [[ -f "${LIBS_DIR}/build/driver/scap.ko" ]]; then
      cp "${LIBS_DIR}/build/driver/scap.ko" "${OUT_KMOD}/${KERNEL_UNAME_R}.ko";
      echo "Build was successful for kmod - out artifact: ${OUT_KMOD}/${KERNEL_UNAME_R}.ko";
      ls -l ${OUT_KMOD}/${KERNEL_UNAME_R}.ko;
    fi
  fi

done

popd;
chown -R 1000:1000 "${DRIVER_OUT_DIR}";


