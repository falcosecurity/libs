#!/bin/bash

if [[ $# -ne 2 ]]; then
  echo "Usage: bash kernel_extract.sh HEADERS_RPMS_DIR HEADERS_EXTRACT_OUT_DIR"
  exit 1
fi

HEADERS_RPMS_DIR="${1}";
HEADERS_EXTRACT_OUT_DIR="${2}";

set -eou pipefail

if [[ -d "${HEADERS_EXTRACT_OUT_DIR}" ]]; then
  printf "\n\n[STATUS] Kernels headers already extracted\n\n";
  exit 0
fi;

mkdir -p "${HEADERS_EXTRACT_OUT_DIR}";
chown -R 1000:1000 "${HEADERS_EXTRACT_OUT_DIR}";

# Extract each kernel source into new directory into HEADERS_EXTRACT_OUT_DIR
for f in "${HEADERS_RPMS_DIR}"/*; do
  if [[ "${f}" == *".rpm"* ]]; then
    KERNEL_HEADERS_PACKAGE_NAME=$(basename "${f}" .rpm)
    OUT="${HEADERS_EXTRACT_OUT_DIR}/${KERNEL_HEADERS_PACKAGE_NAME}";
    if [[ ! -d "${OUT}" ]]; then
      printf "\n\n[STATUS] Extracting ${f} kernel ...\n\n";
      mkdir -p "${OUT}";
      rpm2cpio "${f}" | cpio -D "${OUT}" -idm
      chown -R 1000:1000 "${OUT}";
    else
      printf "\n\n[STATUS] Skipping ${f} kernel extraction, already extracted ...\n\n";
    fi;

  elif [[ "${f}" == *".deb"* ]]; then
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
      printf "\n\n[STATUS] Extracting ${f} kernel ...\n\n";
      mkdir -p "${OUT}";
      pushd "${OUT}";
      ar x "${f}";
      if [[ $(basename data.tar.*) == *".xz"* ]]; then
        tar -h -xf data.tar.*;
      elif [[ $(basename data.tar.*) == *".zst"* ]]; then
        tar -h --use-compress-program=unzstd -xf data.tar.*;
      fi
      popd;
    else
      printf "\n\n[STATUS] Skipping ${f} kernel extraction, already extracted ...\n\n";
    fi;
  fi;
done

for d in "${HEADERS_EXTRACT_OUT_DIR}"/*confs; do
  KERNEL_HEADERS_PACKAGE_NAME=$(echo "${d}" | sed 's/-confs//g');
  # Workaround for ubuntu to avoid readlinks
  if [[ -d "${d}/usr/src" ]]; then
    printf "\n\n[STATUS] Copying confs into $KERNEL_HEADERS_PACKAGE_NAME ubuntu generic headers directory ...\n\n";
    cp -n -a "${d}/usr/src"/*/. "${KERNEL_HEADERS_PACKAGE_NAME}/usr/src"/*/
    chown -R 1000:1000 "${KERNEL_HEADERS_PACKAGE_NAME}";
  fi
  rm -rf "${d}";
done
