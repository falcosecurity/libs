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

option(USE_BUNDLED_LIBBPF "Enable building of the bundled libbpf" ${USE_BUNDLED_DEPS})

if(TARGET lbpf)
	# we already have libbpf
elseif(NOT USE_BUNDLED_LIBBPF)
	include(libelf)
	find_package(ZLIB REQUIRED)
	find_path(LIBBPF_INCLUDE bpf/libbpf.h)
	find_library(LIBBPF_LIB NAMES bpf)
	if(LIBBPF_INCLUDE AND LIBBPF_LIB)
		add_library(lbpf STATIC IMPORTED GLOBAL)
		set_target_properties(lbpf PROPERTIES IMPORTED_LOCATION ${LIBBPF_LIB})
		target_include_directories(lbpf INTERFACE $<BUILD_INTERFACE:${LIBBPF_INCLUDE}>)
		target_link_libraries(lbpf INTERFACE elf ZLIB::ZLIB)

		message(STATUS "Found libbpf: include: ${LIBBPF_INCLUDE}, lib: ${LIBBPF_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system libbpf")
	endif()
else()

	include(libelf)
	find_package(ZLIB REQUIRED)
	set(LIBBPF_SRC "${PROJECT_BINARY_DIR}/libbpf-prefix/src")
	set(LIBBPF_BUILD_DIR "${LIBBPF_SRC}/libbpf-build")
	set(LIBBPF_INCLUDE "${LIBBPF_BUILD_DIR}/root/usr/include")
	set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/root/usr/lib64/libbpf.a")

	foreach(dir ${LIBELF_INCLUDE_DIR})
		string(APPEND LIBELF_COMPILER_STRING "-I${dir} ")
	endforeach()

	foreach(lib ${ZLIB_LIBRARIES})
		get_filename_component(dir ${lib} DIRECTORY)
		string(APPEND ZLIB_LDFLAGS "-L${dir} ")
	endforeach()

	ExternalProject_Add(
		libbpf
		PREFIX "${PROJECT_BINARY_DIR}/libbpf-prefix"
		DEPENDS elf
		URL "https://github.com/libbpf/libbpf/archive/refs/tags/v1.3.0.tar.gz"
		URL_HASH "SHA256=11db86acd627e468bc48b7258c1130aba41a12c4d364f78e184fd2f5a913d861"
		CONFIGURE_COMMAND mkdir -p build root
		BUILD_COMMAND
			make BUILD_STATIC_ONLY=y OBJDIR=${LIBBPF_BUILD_DIR}/build
			DESTDIR=${LIBBPF_BUILD_DIR}/root NO_PKG_CONFIG=1
			"EXTRA_CFLAGS=-fPIC ${LIBELF_COMPILER_STRING} -I${ZLIB_INCLUDE_DIRS}"
			"LDFLAGS=-Wl,-Bstatic" "EXTRA_LDFLAGS=-L${LIBELF_SRC}/libelf/libelf ${ZLIB_LDFLAGS}" -C
			${LIBBPF_SRC}/libbpf/src install install_uapi_headers
		INSTALL_COMMAND ""
		UPDATE_COMMAND ""
		BUILD_BYPRODUCTS ${LIBBPF_LIB}
	)

	add_library(lbpf STATIC IMPORTED GLOBAL)
	set_target_properties(lbpf PROPERTIES IMPORTED_LOCATION ${LIBBPF_LIB})
	file(MAKE_DIRECTORY ${LIBBPF_INCLUDE}) # necessary to make target_include_directories() work
	target_include_directories(lbpf INTERFACE $<BUILD_INTERFACE:${LIBBPF_INCLUDE}>)
	add_dependencies(lbpf libbpf)
	target_link_libraries(lbpf INTERFACE elf ZLIB::ZLIB)

	message(STATUS "Using bundled libbpf: include'${LIBBPF_INCLUDE}', lib: ${LIBBPF_LIB}")
	install(
		FILES "${LIBBPF_LIB}"
		DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "libs-deps"
	)
endif()
