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
	set(ZLIB_SOURCE_DIR "${ZLIB_SRC}/zlib")
	set(ZLIB_INCLUDE "${ZLIB_SRC}/include")
	set(ZLIB_HEADERS "")
	list(
		APPEND
		ZLIB_HEADERS
		"${ZLIB_SOURCE_DIR}/crc32.h"
		"${ZLIB_SOURCE_DIR}/deflate.h"
		"${ZLIB_SOURCE_DIR}/gzguts.h"
		"${ZLIB_SOURCE_DIR}/inffast.h"
		"${ZLIB_SOURCE_DIR}/inffixed.h"
		"${ZLIB_SOURCE_DIR}/inflate.h"
		"${ZLIB_SOURCE_DIR}/inftrees.h"
		"${ZLIB_SOURCE_DIR}/trees.h"
		"${ZLIB_INCLUDE}/zconf.h"
		"${ZLIB_SOURCE_DIR}/zlib.h"
		"${ZLIB_SOURCE_DIR}/zutil.h"
	)
	if(NOT TARGET zlib)
		message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
		falcosecurity_external_project_cache_args(ZLIB_EXTERNAL_PROJECT_CACHE_ARGS)
		if(NOT WIN32)
			# zlib's CMakeLists always defines both the shared ('zlib') and static ('zlibstatic')
			# targets regardless of BUILD_SHARED_LIBS, so build and install only the one we actually
			# consume. This mirrors the old './configure --static' behavior and avoids
			# compiling/linking an unused shared object on static-only (e.g. cross) toolchains. Both
			# targets are named 'z' via OUTPUT_NAME, so the produced artifact is libz<suffix> in
			# either case.
			if(BUILD_SHARED_LIBS)
				set(ZLIB_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
				set(ZLIB_BUILD_TARGET zlib)
				set(ZLIB_LIBRARY_INSTALL_TYPE SHARED_LIBRARY)
			else()
				set(ZLIB_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
				set(ZLIB_BUILD_TARGET zlibstatic)
				set(ZLIB_LIBRARY_INSTALL_TYPE STATIC_LIBRARY)
			endif()
			set(ZLIB_BUILD_DIR "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib-build")
			get_property(ZLIB_IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
			if(ZLIB_IS_MULTI_CONFIG)
				set(ZLIB_BUILD_CONFIG_SUBDIR "$<CONFIG>/")
			else()
				set(ZLIB_BUILD_CONFIG_SUBDIR "")
			endif()
			set(ZLIB_BUILT_LIB
				"${ZLIB_BUILD_DIR}/${ZLIB_BUILD_CONFIG_SUBDIR}libz${ZLIB_LIB_SUFFIX}"
			)
			set(ZLIB_LIB "${ZLIB_SRC}/lib/libz${ZLIB_LIB_SUFFIX}")
			set(ZLIB_INSTALL_SCRIPT "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib-install.cmake")
			file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/zlib-prefix/src")
			file(
				WRITE "${ZLIB_INSTALL_SCRIPT}"
				[=[
if(NOT EXISTS "${ZLIB_BUILT_LIB}")
	message(FATAL_ERROR "Built zlib library not found: ${ZLIB_BUILT_LIB}")
endif()
if(NOT EXISTS "${ZLIB_SOURCE_DIR}/zlib.h")
	message(FATAL_ERROR "zlib.h not found: ${ZLIB_SOURCE_DIR}/zlib.h")
endif()
if(NOT EXISTS "${ZLIB_BUILD_DIR}/zconf.h")
	message(FATAL_ERROR "Generated zconf.h not found: ${ZLIB_BUILD_DIR}/zconf.h")
endif()

file(MAKE_DIRECTORY "${ZLIB_LIB_DIR}" "${ZLIB_INCLUDE}")
file(
	INSTALL DESTINATION "${ZLIB_LIB_DIR}"
	TYPE "${ZLIB_LIBRARY_INSTALL_TYPE}"
	FOLLOW_SYMLINK_CHAIN
	FILES "${ZLIB_BUILT_LIB}"
)
file(
	INSTALL DESTINATION "${ZLIB_INCLUDE}"
	TYPE FILE
	FILES "${ZLIB_SOURCE_DIR}/zlib.h" "${ZLIB_BUILD_DIR}/zconf.h"
)
]=]
			)
			ExternalProject_Add(
				zlib
				PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix"
				SOURCE_DIR "${ZLIB_SOURCE_DIR}"
				URL "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"
				URL_HASH "SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
				CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
						   -DCMAKE_POSITION_INDEPENDENT_CODE=${ENABLE_PIC}
						   -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						   "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}"
						   -DZLIB_BUILD_EXAMPLES=OFF
						   -DCMAKE_INSTALL_PREFIX=${ZLIB_SRC}
						   -DCMAKE_INSTALL_LIBDIR=lib
				CMAKE_CACHE_ARGS ${ZLIB_EXTERNAL_PROJECT_CACHE_ARGS}
				# Build only the target we need so the unused library type is never compiled.
				BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target
							  ${ZLIB_BUILD_TARGET}
				# zlib's own install() installs both targets together, which would fail for the
				# target we did not build; install just the built library + public headers.
				INSTALL_COMMAND
					${CMAKE_COMMAND} "-DZLIB_BUILT_LIB=${ZLIB_BUILT_LIB}"
					"-DZLIB_LIBRARY_INSTALL_TYPE=${ZLIB_LIBRARY_INSTALL_TYPE}"
					"-DZLIB_LIB_DIR=${ZLIB_SRC}/lib" "-DZLIB_INCLUDE=${ZLIB_INCLUDE}"
					"-DZLIB_SOURCE_DIR=${ZLIB_SOURCE_DIR}" "-DZLIB_BUILD_DIR=${ZLIB_BUILD_DIR}" -P
					"${ZLIB_INSTALL_SCRIPT}"
				BUILD_BYPRODUCTS ${ZLIB_LIB}
			)
			install(
				FILES "${ZLIB_LIB}"
				DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
			)
			install(
				FILES ${ZLIB_HEADERS}
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
				SOURCE_DIR "${ZLIB_SOURCE_DIR}"
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
				CMAKE_CACHE_ARGS ${ZLIB_EXTERNAL_PROJECT_CACHE_ARGS}
			)
			install(
				FILES "${ZLIB_LIB}"
				DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps"
			)
			install(
				FILES ${ZLIB_HEADERS}
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
