#!/bin/bash

if [[ ! $# -ge 2 ]]; then
	echo "Usage: bash kernel_download.sh BASE_OUTPUT_DIR KERNELS_FILE FORCE_DOWNLOAD"
  exit 1
fi

BASE_OUTPUT_DIR="${1}";
KERNELS_FILE="${2}";
FORCE_DOWNLOAD="${3}";

HEADERS_DIR="${BASE_OUTPUT_DIR}/headers/";
KERNELS_DIR="${BASE_OUTPUT_DIR}/kernels/";

if [[ ! -z ${FORCE_DOWNLOAD} || ! -d "${HEADERS_DIR}" ]] 
then
  rm -rf ${HEADERS_DIR}; mkdir -p "${HEADERS_DIR}";
  rm -rf ${KERNELS_DIR}; mkdir -p "${KERNELS_DIR}";

  cat "${KERNELS_FILE}" | jq -r '.headers[]' | sed 's/\"//g' > /tmp/headers
  wget -i /tmp/headers --directory-prefix=${HEADERS_DIR} 

  cat "${KERNELS_FILE}" | jq -r '.kernels[]' | sed 's/\"//g' > /tmp/kernels
  wget -i /tmp/kernels --directory-prefix=${KERNELS_DIR}

  chown -R 1000:1000 "${HEADERS_DIR}";
  chown -R 1000:1000 "${KERNELS_DIR}";
else
  echo "Kernels and headers already downloaded"
fi

