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

option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

include(ExternalProjectToolchain)

if(ZLIB_INCLUDE)
	# we already have zlib
elseif(NOT USE_BUNDLED_ZLIB)
	find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
	find_library(ZLIB_LIB NAMES z)
	if(ZLIB_INCLUDE AND ZLIB_LIB)
		message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system zlib")
	endif()
else()
	set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src")
	set(_zlib_source_dir "${ZLIB_SRC}/zlib")
	set(ZLIB_INCLUDE "${ZLIB_SRC}/include")
	set(_zlib_headers "")
	list(
		APPEND
		_zlib_headers
		"${_zlib_source_dir}/crc32.h"
		"${_zlib_source_dir}/deflate.h"
		"${_zlib_source_dir}/gzguts.h"
		"${_zlib_source_dir}/inffast.h"
		"${_zlib_source_dir}/inffixed.h"
		"${_zlib_source_dir}/inflate.h"
		"${_zlib_source_dir}/inftrees.h"
		"${_zlib_source_dir}/trees.h"
		"${ZLIB_INCLUDE}/zconf.h"
		"${_zlib_source_dir}/zlib.h"
		"${_zlib_source_dir}/zutil.h"
	)
	if(NOT TARGET zlib)
		message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
		falcosecurity_external_project_cache_args(_zlib_external_project_cache_args)
		if(NOT WIN32)
			# zlib's CMakeLists always defines both the shared ('zlib') and static ('zlibstatic')
			# targets regardless of BUILD_SHARED_LIBS, so build and install only the one we actually
			# consume. This mirrors the old './configure --static' behavior and avoids
			# compiling/linking an unused shared object on static-only (e.g. cross) toolchains. Both
			# targets are named 'z' via OUTPUT_NAME, so the produced artifact is libz<suffix> in
			# either case.
			if(BUILD_SHARED_LIBS)
				set(ZLIB_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
				set(_zlib_build_target zlib)
				set(_zlib_library_install_type SHARED_LIBRARY)
			else()
				set(ZLIB_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
				set(_zlib_build_target zlibstatic)
				set(_zlib_library_install_type STATIC_LIBRARY)
			endif()
			set(_zlib_build_dir "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib-build")
			get_property(_zlib_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
			if(_zlib_is_multi_config)
				set(_zlib_build_config_subdir "$<CONFIG>/")
				set(_zlib_build_config_args --config $<CONFIG>)
			else()
				set(_zlib_build_config_subdir "")
				set(_zlib_build_config_args)
			endif()
			set(_zlib_built_lib
				"${_zlib_build_dir}/${_zlib_build_config_subdir}libz${ZLIB_LIB_SUFFIX}"
			)
			set(ZLIB_LIB "${ZLIB_SRC}/lib/libz${ZLIB_LIB_SUFFIX}")
			set(_zlib_install_script "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib-install.cmake")
			file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/zlib-prefix/src")
			file(
				WRITE "${_zlib_install_script}"
				[=[
if(NOT EXISTS "${_zlib_built_lib}")
	message(FATAL_ERROR "Built zlib library not found: ${_zlib_built_lib}")
endif()
if(NOT EXISTS "${_zlib_source_dir}/zlib.h")
	message(FATAL_ERROR "zlib.h not found: ${_zlib_source_dir}/zlib.h")
endif()
if(NOT EXISTS "${_zlib_build_dir}/zconf.h")
	message(FATAL_ERROR "Generated zconf.h not found: ${_zlib_build_dir}/zconf.h")
endif()

file(MAKE_DIRECTORY "${_zlib_lib_dir}" "${ZLIB_INCLUDE}")
file(
	INSTALL DESTINATION "${_zlib_lib_dir}"
	TYPE "${_zlib_library_install_type}"
	FOLLOW_SYMLINK_CHAIN
	FILES "${_zlib_built_lib}"
)
file(
	INSTALL DESTINATION "${ZLIB_INCLUDE}"
	TYPE FILE
	FILES "${_zlib_source_dir}/zlib.h" "${_zlib_build_dir}/zconf.h"
)
]=]
			)
			ExternalProject_Add(
				zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				SOURCE_DIR "${_zlib_source_dir}"
				URL "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
				URL_HASH "SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
				CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
						   -DCMAKE_POSITION_INDEPENDENT_CODE=${ENABLE_PIC}
						   -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						   "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}"
						   -DZLIB_BUILD_EXAMPLES=OFF
						   -DCMAKE_INSTALL_PREFIX=${ZLIB_SRC}
						   -DCMAKE_INSTALL_LIBDIR=lib
				CMAKE_CACHE_ARGS ${_zlib_external_project_cache_args}
				# Build only the target we need so the unused library type is never compiled.
				BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> ${_zlib_build_config_args}
							  --target ${_zlib_build_target}
				# zlib's own install() installs both targets together, which would fail for the
				# target we did not build; install just the built library + public headers.
				INSTALL_COMMAND
					${CMAKE_COMMAND} "-D_zlib_built_lib=${_zlib_built_lib}"
					"-D_zlib_library_install_type=${_zlib_library_install_type}"
					"-D_zlib_lib_dir=${ZLIB_SRC}/lib" "-DZLIB_INCLUDE=${ZLIB_INCLUDE}"
					"-D_zlib_source_dir=${_zlib_source_dir}" "-D_zlib_build_dir=${_zlib_build_dir}"
					-P "${_zlib_install_script}"
				BUILD_BYPRODUCTS ${ZLIB_LIB}
			)
			install(
				FILES "${ZLIB_LIB}"
				DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
			)
			install(
				FILES ${_zlib_headers}
				DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/zlib"
				COMPONENT "libs-deps"
			)
		else()
			if(BUILD_SHARED_LIBS)
				set(ZLIB_LIB_SUFFIX "${CMAKE_SHARED_LIBRARY_SUFFIX}")
				set(ZLIB_LIB "${ZLIB_SRC}/lib/zlib$<$<CONFIG:Debug>:d>${ZLIB_LIB_SUFFIX}")
			else()
				set(ZLIB_LIB_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}")
				set(ZLIB_LIB "${ZLIB_SRC}/lib/zlibstatic$<$<CONFIG:Debug>:d>${ZLIB_LIB_SUFFIX}")
			endif()
			ExternalProject_Add(
				zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				SOURCE_DIR "${_zlib_source_dir}"
				URL "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
				URL_HASH "SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
				BUILD_IN_SOURCE 1
				BUILD_BYPRODUCTS ${ZLIB_LIB}
				CMAKE_ARGS -DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW
						   -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
						   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
						   -DCMAKE_POSITION_INDEPENDENT_CODE=${ENABLE_PIC}
						   -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						   "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}"
						   -DZLIB_BUILD_EXAMPLES=OFF
						   -DCMAKE_INSTALL_PREFIX=${ZLIB_SRC}
						   -DCMAKE_INSTALL_LIBDIR=lib
				CMAKE_CACHE_ARGS ${_zlib_external_project_cache_args}
			)
			install(
				FILES "${ZLIB_LIB}"
				DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
			)
			install(
				FILES ${_zlib_headers}
				DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/zlib"
				COMPONENT "libs-deps"
			)
		endif()
	endif()
endif()

if(NOT TARGET zlib)
	add_custom_target(zlib)
endif()

include_directories(${ZLIB_INCLUDE})
