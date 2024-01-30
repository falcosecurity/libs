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

option(USE_BUNDLED_RE2 "Enable building of the bundled RE2" ${USE_BUNDLED_DEPS})

if(RE2_INCLUDE)
	message(STATUS "Using re2: include: ${RE2_INCLUDE}, lib: ${RE2_LIB}")
elseif(NOT USE_BUNDLED_RE2)
	find_path(RE2_INCLUDE re2/re2.h PATH_SUFFIXES re2)
	find_library(RE2_LIB NAMES re2)
	if(RE2_INCLUDE AND RE2_LIB)
		message(STATUS "Found re2: include: ${RE2_INCLUDE}, lib: ${RE2_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system re2")
	endif()
else()
	set(RE2_SRC "${PROJECT_BINARY_DIR}/re2-prefix/src/re2")
	set(RE2_INCLUDE "${RE2_SRC}/include")
	set(RE2_DIR "${RE2_SRC}/lib/cmake/re2")
	set(RE2_URL "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz")
	set(RE2_URL_HASH "SHA256=f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f")
	if(BUILD_SHARED_LIBS)
		set(RE2_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(RE2_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()

	message(STATUS "Using bundled re2 in '${RE2_SRC}'")

	if(NOT WIN32)
		set(RE2_LIB "${RE2_SRC}/lib/libre2${RE2_LIB_SUFFIX}")
		set(RE2_LIB_PATTERN "libre2*")
		ExternalProject_Add(re2
			PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
			URL "${RE2_URL}"
			URL_HASH "${RE2_URL_HASH}"
			BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
			BUILD_BYPRODUCTS ${RE2_LIB}
			CMAKE_ARGS
				-DCMAKE_INSTALL_LIBDIR=lib
				-DRE2_BUILD_TESTING=OFF
				-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
				-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
	else()
		set(RE2_LIB "${RE2_SRC}/lib/re2.lib")
		set(RE2_LIB_PATTERN "re2.lib")
		# see: https://cmake.org/cmake/help/latest/policy/CMP0091.html
		if(CMAKE_VERSION VERSION_LESS 3.15.0)
			ExternalProject_Add(re2
				PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
				URL "${RE2_URL}"
				URL_HASH "${RE2_URL_HASH}"
				BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
				BUILD_BYPRODUCTS ${RE2_LIB}
				CMAKE_ARGS
					-DCMAKE_CXX_FLAGS_DEBUG=${FALCOSECURITY_LIBS_DEBUG_FLAGS}
					-DCMAKE_CXX_FLAGS_RELEASE=${FALCOSECURITY_LIBS_RELEASE_FLAGS}
					-DCMAKE_INSTALL_LIBDIR=lib
					-DRE2_BUILD_TESTING=OFF
					-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
					-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
		else()
			ExternalProject_Add(re2
				PREFIX "${PROJECT_BINARY_DIR}/re2-prefix"
				URL "${RE2_URL}"
				URL_HASH "${RE2_URL_HASH}"
				BINARY_DIR "${PROJECT_BINARY_DIR}/re2-prefix/build"
				BUILD_BYPRODUCTS ${RE2_LIB}
				CMAKE_ARGS
					-DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW
					-DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
					-DCMAKE_INSTALL_LIBDIR=lib
					-DRE2_BUILD_TESTING=OFF
					-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
					-DCMAKE_INSTALL_PREFIX=${RE2_SRC})
		endif()
	endif()

	install(DIRECTORY ${RE2_SRC}/lib/ DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
			FILES_MATCHING PATTERN ${RE2_LIB_PATTERN})
	install(DIRECTORY "${RE2_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps")
endif()

if(NOT TARGET re2)
	add_custom_target(re2)
endif()

include_directories("${RE2_INCLUDE}")
