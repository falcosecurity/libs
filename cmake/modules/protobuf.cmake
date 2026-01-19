# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})

if(PROTOBUF_INCLUDE)
	# we already have protobuf
elseif(NOT USE_BUNDLED_PROTOBUF)
	find_program(PROTOC NAMES protoc)
	find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
	find_library(PROTOBUF_LIB NAMES protobuf)
	if(PROTOC
	   AND PROTOBUF_INCLUDE
	   AND PROTOBUF_LIB
	)
		message(
			STATUS
				"Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}"
		)
	else()
		message(FATAL_ERROR "Couldn't find system protobuf")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(PROTOBUF_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	include(zlib)

	set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
	set(PROTOBUF_INSTALL_DIR "${PROTOBUF_SRC}")
	set(PROTOC "${PROTOBUF_INSTALL_DIR}/bin/protoc")
	set(PROTOBUF_INCLUDE "${PROTOBUF_INSTALL_DIR}/include/")
	set(PROTOBUF_LIB
		"${PROTOBUF_INSTALL_DIR}/lib/libprotobuf${PROTOBUF_LIB_SUFFIX}"
		CACHE PATH "Path to libprotobuf"
	)
	set(PROTOC_LIB "${PROTOBUF_INSTALL_DIR}/lib/libprotoc${PROTOBUF_LIB_SUFFIX}")

	message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")

	if(NOT TARGET protobuf)
		ExternalProject_Add(
			protobuf
			PREFIX "${PROJECT_BINARY_DIR}/protobuf-prefix"
			DEPENDS zlib
			URL "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-3.21.12.tar.gz"
			URL_HASH "SHA256=4eab9b524aa5913c6fffb20b2a8abf5ef7f95a80bc0701f3a6dbb4c607f73460"
			BINARY_DIR "${PROJECT_BINARY_DIR}/protobuf-prefix/build"
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_LIB}
			CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${PROTOBUF_INSTALL_DIR}
					   -DCMAKE_INSTALL_LIBDIR=lib
					   -DCMAKE_POSITION_INDEPENDENT_CODE=${ENABLE_PIC}
					   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
					   -Dprotobuf_BUILD_TESTS=OFF
					   -Dprotobuf_BUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
					   -Dprotobuf_WITH_ZLIB=ON
					   -DZLIB_INCLUDE_DIR=${ZLIB_INCLUDE}
					   -DZLIB_LIBRARY=${ZLIB_LIB}
		)
		install(
			FILES "${PROTOBUF_LIB}"
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			FILES "${PROTOC_LIB}"
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
		install(
			DIRECTORY "${PROTOBUF_INCLUDE}"
			DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
	endif()
endif()

if(NOT TARGET protobuf)
	add_custom_target(protobuf)
endif()

include_directories("${PROTOBUF_INCLUDE}")
