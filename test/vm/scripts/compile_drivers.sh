#!/bin/bash

if [[ $# -ne 5 ]]; then
  echo "Usage: bash compile_drivers.sh LLC CLANG GCC KMOD BPF"
  exit 1
fi

printf "\n\n[STATUS] Build driver artifacts for extracted kernel headers, script continues on failure ...\n\n"

DIR_EXTRACTED_KERNEL_HEADERS_SUB_DIRS="/headers"; # host dir mounted in container, it is a directory with sub directories containing extracted kernel headers
DRIVER_OUT_DIR="/vm/build/driver"; # host dir mounted in container
LIBS_TAR_GZ="/vm/build/libs-src.tar.gz"; # host dir mounted in container

if [[ ! -f ${LIBS_TAR_GZ} ]]; then
	printf "\n\n[STATUS] FAILED Container requires libs source in libs-src.tar.gz format and mounted to /vm/build/libs-src.tar.gz in container\n\n"
  exit 1
fi

LLC="${1}"; # only needed for eBPF
CLANG="${2}"; # only needed for eBPF
GCC="${3}"; # only needed for kmod
KMOD="${4}";                    
BPF="${5}";

set -eou pipefail

LIBS_DIR="/libs"; # dir mounted in container
rm -f "${LIBS_DIR}";
mkdir -p "${DRIVER_OUT_DIR}";
mkdir -p "${LIBS_DIR}/build";
tar -xvf ${LIBS_TAR_GZ} -C ${LIBS_DIR}/;  # fresh extraction of libs src in container, clean build dir

cmake -DUSE_BUNDLED_DEPS=ON \
    -DBUILD_BPF="${BPF}" \
    -DBUILD_DRIVER="${KMOD}" \
    -DBUILD_LIBSCAP_GVISOR=OFF \
    -DCREATE_TEST_TARGETS=OFF \
    -S "${LIBS_DIR}" \
    -B "${LIBS_DIR}/build"

CLANG_VERSION=$(echo ${CLANG} | sed "s/.*\///");
GCC_VERSION=$(echo ${GCC} | sed "s/.*\///");
if [[ "${BPF}" == *"ON"* ]]; then
  OUT_BPF="${DRIVER_OUT_DIR}/${CLANG_VERSION}";
  mkdir -p "${OUT_BPF}";
  if [[ ! -d "${OUT_BPF}" ]];  then
    echo >&2 "Failed to create ${OUT_BPF}"
    exit 1
  fi
  chown -R 1000:1000 "${OUT_BPF}";
elif [[ "${KMOD}" == *"ON"* ]]; then
  OUT_KMOD="${DRIVER_OUT_DIR}/${GCC_VERSION}";
  mkdir -p "${OUT_KMOD}";
  if [[ ! -d "${OUT_KMOD}" ]];  then
    echo >&2 "Failed to create ${OUT_KMOD}"
    exit 1
  fi
  chown -R 1000:1000 "${OUT_KMOD}";
fi

for d in "${DIR_EXTRACTED_KERNEL_HEADERS_SUB_DIRS}"/*; do

  KERNEL_UNAME_R=$(basename "${d}" | sed "s/.*devel-//" );
  # RPM based extracted headers sources dir
  SOURCES="${d}/usr/src/kernels/*"
  if [[ "${d}" == *"generic" ]]; then
    # DEB ubuntu based extracted headers sources dir
    SOURCES="${d}/usr/src/*";
  fi

  if [[ "${BPF}" == *"ON"* ]]; then
    printf "\n\n[STATUS] IN PROGRESS bpf ${KERNEL_UNAME_R} w/ ${CLANG_VERSION}\n\n";
    "${CLANG}" --version;
    rm -f "${LIBS_DIR}/build/driver/bpf/probe.o";
    make LLC="${LLC}" CLANG="${CLANG}" \
    KERNELDIR=${SOURCES} -B -C "${LIBS_DIR}/build/driver/bpf" || true

    if [[ -f "${LIBS_DIR}/build/driver/bpf/probe.o" ]]; then
      cp "${LIBS_DIR}/build/driver/bpf/probe.o" "${OUT_BPF}/${KERNEL_UNAME_R}.o";
      printf "\n\n[STATUS] SUCCESS bpf - out artifact: ${OUT_BPF}/${KERNEL_UNAME_R}.o\n\n";
      ls -l ${OUT_BPF}/${KERNEL_UNAME_R}.o;
    fi
  elif [[ -x ${GCC} && "${KMOD}" == *"ON"* ]]; then # fail safe as system standard GCC is selected when "${GCC}" not installed
    printf "\n\n[STATUS] IN PROGRESS kmod ${KERNEL_UNAME_R} w/ ${GCC_VERSION}\n\n";
    rm -f "${LIBS_DIR}/build/driver/scap.ko";
    rm -f /usr/bin/gcc;
    cp -f "${GCC}" /usr/bin/gcc;
    /usr/bin/gcc --version;
    make \
    KERNELDIR=${SOURCES} -B -C "${LIBS_DIR}/build/driver/" || true

    if [[ -f "${LIBS_DIR}/build/driver/scap.ko" ]]; then
      cp "${LIBS_DIR}/build/driver/scap.ko" "${OUT_KMOD}/${KERNEL_UNAME_R}.ko";
      printf "\n\n[STATUS] SUCCESS kmod - out artifact: ${OUT_KMOD}/${KERNEL_UNAME_R}.ko\n\n";
      ls -l ${OUT_KMOD}/${KERNEL_UNAME_R}.ko;
    fi
  fi

done

chown -R 1000:1000 "${DRIVER_OUT_DIR}";
