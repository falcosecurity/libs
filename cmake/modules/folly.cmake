# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
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

#
# facebook/folly (https://github.com/facebook/folly) Used for folly::ConcurrentHashMap in the
# thread-safe thread manager.
#

option(USE_BUNDLED_FOLLY "Enable building of the bundled folly" ${USE_BUNDLED_DEPS})

if(FOLLY_INCLUDE_DIR)
	# we already have folly
elseif(NOT USE_BUNDLED_FOLLY)
	find_package(folly CONFIG QUIET)
	if(folly_FOUND)
		get_target_property(FOLLY_INCLUDE_DIR Folly::folly INTERFACE_INCLUDE_DIRECTORIES)
		# Use the imported target directly for linking
		set(FOLLY_LIB Folly::folly)
		message(STATUS "Found system folly: include: ${FOLLY_INCLUDE_DIR}")
	else()
		# Fallback to manual search
		find_path(FOLLY_INCLUDE_DIR folly/concurrency/ConcurrentHashMap.h)
		find_library(FOLLY_LIB NAMES folly)
		if(FOLLY_INCLUDE_DIR AND FOLLY_LIB)
			message(STATUS "Found folly: include: ${FOLLY_INCLUDE_DIR}, lib: ${FOLLY_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system folly")
		endif()
	endif()
else()
	set(FOLLY_SRC "${PROJECT_BINARY_DIR}/folly-prefix/src/folly")
	set(FOLLY_INSTALL_DIR "${PROJECT_BINARY_DIR}/folly-prefix/install")
	set(FOLLY_INCLUDE_DIR "${FOLLY_INSTALL_DIR}/include")

	if(BUILD_SHARED_LIBS)
		set(FOLLY_LIB_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
		set(FOLLY_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(FOLLY_LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
		set(FOLLY_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()

	set(FOLLY_LIB "${FOLLY_INSTALL_DIR}/lib/${FOLLY_LIB_PREFIX}folly${FOLLY_LIB_SUFFIX}")

	if(NOT TARGET folly)
		message(STATUS "Using bundled folly in '${FOLLY_SRC}'")
		set(FOLLY_SRC_URL
			"https://github.com/facebook/folly/archive/refs/tags/v2024.12.02.00.tar.gz"
		)
		set(FOLLY_SRC_URL_HASH
			"SHA256=8956a72cb356e0e81e3a2de28d24b7a498aa0ad48d5bfba0c9b1e2b0e925fb0b"
		)

		ExternalProject_Add(
			folly
			PREFIX "${PROJECT_BINARY_DIR}/folly-prefix"
			URL "${FOLLY_SRC_URL}"
			URL_HASH "${FOLLY_SRC_URL_HASH}"
			CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${FOLLY_INSTALL_DIR}
					   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
					   -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
					   -DCMAKE_CXX_STANDARD=17
					   -DCMAKE_POSITION_INDEPENDENT_CODE=${ENABLE_PIC}
					   -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
					   -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
					   -DBUILD_TESTS=OFF
					   -DBUILD_BENCHMARKS=OFF
			BUILD_BYPRODUCTS ${FOLLY_LIB}
		)

		install(
			DIRECTORY "${FOLLY_INSTALL_DIR}/lib/"
			DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
			FILES_MATCHING
			PATTERN "${FOLLY_LIB_PREFIX}folly*"
		)
		install(
			DIRECTORY "${FOLLY_INCLUDE_DIR}/folly"
			DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "libs-deps"
		)
	endif()
endif()

if(NOT TARGET folly)
	add_custom_target(folly)
endif()

# Only add include directories if not using the imported target (Folly::folly already provides its
# own include directories)
if(NOT folly_FOUND)
	include_directories("${FOLLY_INCLUDE_DIR}")
endif()
