# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

option(USE_BUNDLED_LIBBPF "Enable building of the bundled libbpf" ${USE_BUNDLED_DEPS})

if(LIBBPF_INCLUDE)
    # we already have libbpf
elseif(NOT USE_BUNDLED_LIBBPF)
    find_path(LIBBPF_INCLUDE bpf/libbpf.h)
    find_library(LIBBPF_LIB NAMES bpf)
    if(LIBBPF_INCLUDE AND LIBBPF_LIB)
        message(STATUS "Found libbpf: include: ${LIBBPF_INCLUDE}, lib: ${LIBBPF_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libbpf")
    endif()
else()
    include(zlib)
    include(libelf)
    set(LIBBPF_SRC "${PROJECT_BINARY_DIR}/libbpf-prefix/src")
    set(LIBBPF_BUILD_DIR "${LIBBPF_SRC}/libbpf-build")
    set(LIBBPF_INCLUDE "${LIBBPF_BUILD_DIR}/root/usr/include")
    set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/root/usr/lib64/libbpf.a")
    ExternalProject_Add(
        libbpf
        PREFIX "${PROJECT_BINARY_DIR}/libbpf-prefix"
        DEPENDS zlib libelf
        URL "https://github.com/libbpf/libbpf/archive/refs/tags/v1.3.0.tar.gz"
        URL_HASH
        "SHA256=11db86acd627e468bc48b7258c1130aba41a12c4d364f78e184fd2f5a913d861"
        CONFIGURE_COMMAND mkdir -p build root
        BUILD_COMMAND make BUILD_STATIC_ONLY=y OBJDIR=${LIBBPF_BUILD_DIR}/build DESTDIR=${LIBBPF_BUILD_DIR}/root NO_PKG_CONFIG=1 "EXTRA_CFLAGS=-fPIC -I${LIBELF_INCLUDE} -I${ZLIB_INCLUDE}" "LDFLAGS=-Wl,-Bstatic" "EXTRA_LDFLAGS=-L${LIBELF_SRC}/libelf/libelf -L${ZLIB_SRC}" -C ${LIBBPF_SRC}/libbpf/src install install_uapi_headers
        INSTALL_COMMAND ""
        UPDATE_COMMAND ""
        BUILD_BYPRODUCTS ${LIBBPF_LIB}
    )
    message(STATUS "Using bundled libbpf: include'${LIBBPF_INCLUDE}', lib: ${LIBBPF_LIB}")
    install(FILES "${LIBBPF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
    install(DIRECTORY "${LIBBPF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
endif()

if(NOT TARGET libbpf)
    add_custom_target(libbpf)
endif()

include_directories(${LIBBPF_INCLUDE})
