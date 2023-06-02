#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage: bash kernel_extract.sh HEADERS_RPMS_DIR HEADERS_EXTRACT_OUT_DIR"
  exit 1
fi

HEADERS_RPMS_DIR="${1}";
HEADERS_EXTRACT_OUT_DIR="${2}";

set -eou pipefail

if [[ ! -d "${HEADERS_EXTRACT_OUT_DIR}" ]]; then
  mkdir -p "${HEADERS_EXTRACT_OUT_DIR}";
  chown -R 1000:1000 "${HEADERS_EXTRACT_OUT_DIR}";
else
  echo "Kernels headers already extracted";
  exit 0
fi;

FILES="${HEADERS_RPMS_DIR}/*"
# Extract each kernel source into new directory into HEADERS_EXTRACT_OUT_DIR
for f in $FILES
do
  if [[ "${f}" == *".rpm"* ]]; then
    
    KERNEL_HEADERS_PACKAGE_NAME=$(basename "${f}" .rpm)
    OUT="${HEADERS_EXTRACT_OUT_DIR}/${KERNEL_HEADERS_PACKAGE_NAME}";
    if [[ ! -d "${OUT}" ]]; then
      echo "Extracting ${f} kernel ...";
      mkdir -p "${OUT}";
      rpm2cpio "${f}" | cpio -D "${OUT}" -idm
      chown -R 1000:1000 "${OUT}";
    else
      echo "Skipping ${f} kernel extraction, already extracted ...";
    fi;
  fi;

  if [[ "${f}" == *".deb"* ]]; then
    KERNEL_HEADERS_PACKAGE_NAME=$(echo "${f}" | grep -o -P "(?<=linux-headers-).*(?=_[0-9])")
    # Workaround for ubuntu to avoid readlinks
    if [[ $KERNEL_HEADERS_PACKAGE_NAME == *"generic"* ]]; then
      KERNEL_HEADERS_PACKAGE_NAME="${KERNEL_HEADERS_PACKAGE_NAME}-confs";
    fi
    if [[ $KERNEL_HEADERS_PACKAGE_NAME != *"confs"* ]]; then
      KERNEL_HEADERS_PACKAGE_NAME="${KERNEL_HEADERS_PACKAGE_NAME}-generic";
    fi

    OUT="${HEADERS_EXTRACT_OUT_DIR}/${KERNEL_HEADERS_PACKAGE_NAME}";
    if [[ ! -d "${OUT}" ]]; then
      echo "Extracting ${f} kernel ...";
      mkdir -p "${OUT}";
      pushd "${OUT}";
      ar x "${f}";
      if [[ $(basename data.tar.*) == *".xz"* ]]; then
        tar -h -xf data.tar.*;
      fi
      if [[ $(basename data.tar.*) == *".zst"* ]]; then
        tar -h --use-compress-program=unzstd -xf data.tar.*;
      fi
      popd;
    else
      echo "Skipping ${f} kernel extraction, already extracted ...";
    fi;
  fi;
done

DIRS="${HEADERS_EXTRACT_OUT_DIR}/*confs";
for d in $DIRS
do
  if [[ "${d}" == *"confs"* ]]; then
    KERNEL_HEADERS_PACKAGE_NAME=$(echo "${d}" | sed 's/-confs//g');
    # Workaround for ubuntu to avoid readlinks
    echo "Copying confs into $KERNEL_HEADERS_PACKAGE_NAME ubuntu generic headers directory ...";
    cp -n -a ${d}/usr/src/*/. ${KERNEL_HEADERS_PACKAGE_NAME}/usr/src/*/
    chown -R 1000:1000 "${KERNEL_HEADERS_PACKAGE_NAME}";
    rm -rf "${d}";
  fi;
done


