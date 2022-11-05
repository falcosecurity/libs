#!/bin/bash

echo "Building scap-open"

LIBS_DIR="/falco-libs"; # dir mounted in container
mkdir -p "${LIBS_DIR}/build";

LIBS_TAR_GZ="/driver-sanity/build/libs-src.tar.gz"; # host dir mounted in container

if [[ ! -f ${LIBS_TAR_GZ} ]]; then
	echo "Container requires libs source in libs-src.tar.gz format and mounted to /driver-sanity/build/libs-src.tar.gz in container"
  exit 1
fi

LIBS_DIR="/libs";
mkdir -p "${LIBS_DIR}/build";
tar -xvf ${LIBS_TAR_GZ} -C ${LIBS_DIR}/;  # fresh extraction of libs src in container, clean build dir

pushd "${LIBS_DIR}/build";
cmake -DFALCOSECURITY_LIBS_VERSION="sanity" -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=OFF -DBUILD_DRIVER=OFF -DBUILD_LIBSCAP_GVISOR=OFF ..;
make scap-open -B;
popd;

cp -f ${LIBS_DIR}/build/libscap/examples/01-open/scap-open /driver-sanity/build/scap-open;
chown -R 1000:1000 /driver-sanity/build/;
chown -R 1000:1000 "${LIBS_DIR}/build";
