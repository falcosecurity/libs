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

option(USE_BUNDLED_FMT "Enable building of the bundled fmt" ${USE_BUNDLED_DEPS})

include(ExternalProjectToolchain)

if(FMT_INCLUDE_DIR)
	# we already have fmt
elseif(NOT USE_BUNDLED_FMT)
	find_path(FMT_INCLUDE_DIR fmt/core.h)
	find_library(FMT_LIB NAMES fmt)
	if(FMT_INCLUDE_DIR AND FMT_LIB)
		message(STATUS "Found fmt: include: ${FMT_INCLUDE_DIR}, lib: ${FMT_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system fmt")
	endif()
else()
	set(FMT_SRC "${PROJECT_BINARY_DIR}/fmt-prefix/src/fmt")
	set(FMT_INCLUDE_DIR "${FMT_SRC}/include")

	set(FMT_LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
	set(FMT_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	# fmt uses DEBUG_POSTFIX "d" (libfmtd.a) when CMAKE_BUILD_TYPE is Debug.
	set(_FMT_LIB_BASENAME "fmt")
	if(CMAKE_BUILD_TYPE)
		string(TOUPPER "${CMAKE_BUILD_TYPE}" _FMT_BUILD_UPPER)
		if(_FMT_BUILD_UPPER STREQUAL "DEBUG")
			set(_FMT_LIB_BASENAME "fmtd")
		endif()
	endif()
	set(FMT_BUILD_DIR "${PROJECT_BINARY_DIR}/fmt-prefix/build")
	set(FMT_LIB "${FMT_BUILD_DIR}/${FMT_LIB_PREFIX}${_FMT_LIB_BASENAME}${FMT_LIB_SUFFIX}")

	if(NOT TARGET fmt)
		message(STATUS "Using bundled fmt in '${FMT_SRC}'")
		falcosecurity_external_project_cache_args(FMT_EXTERNAL_PROJECT_CACHE_ARGS)

		ExternalProject_Add(
			fmt
			PREFIX "${PROJECT_BINARY_DIR}/fmt-prefix"
			URL "https://github.com/fmtlib/fmt/archive/refs/tags/10.2.1.tar.gz"
			URL_HASH "SHA256=1250e4cc58bf06ee631567523f48848dc4596133e163f02615c97f78bab6c811"
			BINARY_DIR "${FMT_BUILD_DIR}"
			CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DFMT_DOC=OFF -DFMT_TEST=OFF
					   -DFMT_INSTALL=OFF
			CMAKE_CACHE_ARGS ${FMT_EXTERNAL_PROJECT_CACHE_ARGS}
			BUILD_BYPRODUCTS ${FMT_LIB}
			INSTALL_COMMAND ""
		)
	endif()
endif()

if(NOT TARGET fmt)
	add_custom_target(fmt)
endif()

include_directories("${FMT_INCLUDE_DIR}")
