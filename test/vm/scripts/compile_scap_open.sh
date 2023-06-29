#!/bin/bash

set -eou pipefail

echo "Building scap-open"

LIBS_DIR="/libs"; # dir mounted in container
mkdir -p "${LIBS_DIR}/build";
LIBS_TAR_GZ="/vm/build/libs-src.tar.gz"; # host dir mounted in container

if [[ ! -f ${LIBS_TAR_GZ} ]]; then
  echo "Container requires libs source in libs-src.tar.gz format and mounted to /vm/build/libs-src.tar.gz in container"
  exit 1
fi

tar -xvf ${LIBS_TAR_GZ} -C ${LIBS_DIR}/;  # fresh extraction of libs src in container, clean build dir

cmake -DUSE_BUNDLED_DEPS=ON \
  -DBUILD_BPF=OFF \
  -DBUILD_DRIVER=OFF \
  -DBUILD_LIBSCAP_GVISOR=OFF \
  -S "${LIBS_DIR}" \
  -B "${LIBS_DIR}/build"

make -C "${LIBS_DIR}/build" -j"$(nproc)" scap-open

cp -f ${LIBS_DIR}/build/libscap/examples/01-open/scap-open /vm/build/scap-open;
chown -R 1000:1000 /vm/build/;
chown -R 1000:1000 "${LIBS_DIR}/build";
