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

option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})

if(PROTOBUF_INCLUDE)
	# we already have protobuf
elseif(NOT USE_BUNDLED_PROTOBUF)
	find_program(PROTOC NAMES protoc)
	find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
	find_library(PROTOBUF_LIB NAMES protobuf)
	if(PROTOC AND PROTOBUF_INCLUDE AND PROTOBUF_LIB)
		message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system protobuf")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(PROTOBUF_CONFIGURE_FLAGS --enable-shared --disable-static)
	else()
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(PROTOBUF_CONFIGURE_FLAGS --disable-shared --enable-static)
	endif()
	include(zlib)

	set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
	set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
	set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include/")
	set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf${PROTOBUF_LIB_SUFFIX}" CACHE PATH "Path to libprotobuf")
	set(PROTOC_LIB "${PROTOBUF_SRC}/target/lib/libprotoc${PROTOBUF_LIB_SUFFIX}")
	set(PROTOBUF_INSTALL_DIR "${PROTOBUF_SRC}/target")

	if(NOT TARGET protobuf)
		message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
		ExternalProject_Add(protobuf
			PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
			DEPENDS zlib
			URL "https://github.com/protocolbuffers/protobuf/releases/download/v3.20.3/protobuf-cpp-3.20.3.tar.gz"
			URL_HASH "SHA256=e51cc8fc496f893e2a48beb417730ab6cbcb251142ad8b2cd1951faa5c76fe3d"
			# TODO what if using system zlib?
			CONFIGURE_COMMAND CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib ${PROTOBUF_CONFIGURE_FLAGS} --prefix=${PROTOBUF_INSTALL_DIR}
			BUILD_COMMAND make
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
			INSTALL_COMMAND make install)
		install(FILES "${PROTOBUF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(FILES "${PROTOC_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${PROTOBUF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET protobuf)
	add_custom_target(protobuf)
endif()

include_directories("${PROTOBUF_INCLUDE}")
