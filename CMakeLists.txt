# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Prior to doing anything, we make sure that we aren't trying to
# run cmake in-tree.
if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
	message(FATAL_ERROR
		"Looks like you are trying to run CMake from the base source directory.\n"
		"** RUNNING CMAKE FROM THE BASE DIRECTORY WILL NOT WORK **\n"
		"To Fix:\n"
		" 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
		" 2. Create a build directory from here. ex: mkdir build\n"
		" 3. cd into that directory. ex: cd build\n"
		" 4. Run cmake from the build directory. ex: cmake ..\n"
		" 5. Run make from the build directory. ex: make\n"
		"Full paste-able example:\n"
		"( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )")
endif()

cmake_minimum_required(VERSION 3.12)

# Enable MACOSX_RPATH (and keep CMake from complaining).
if(POLICY CMP0042)
	cmake_policy(SET CMP0042 NEW)
endif()

# Enable CMAKE_MSVC_RUNTIME_LIBRARY on Windows + CMake >= 3.15 and link
# with the static (MultiThreaded) CRT unless instructed otherwise.
if(NOT (CMAKE_MSVC_RUNTIME_LIBRARY OR BUILD_SHARED_LIBS))
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
if(POLICY CMP0091)
	cmake_policy(SET CMP0091 NEW)
endif()

if(POLICY CMP0135)
	cmake_policy(SET CMP0135 NEW)
endif()

project(falcosecurity-libs)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)
option(MINIMAL_BUILD "Produce a minimal build with only the essential features (no container metadata)" OFF)
option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)
option(USE_BUNDLED_DRIVER "Use the driver/ subdirectory in the build process (only available in Linux)" ON)
option(ENABLE_DRIVERS_TESTS "Enable driver tests (bpf, kernel module, modern bpf)" OFF)
option(ENABLE_LIBSCAP_TESTS "Enable libscap unit tests" OFF)
option(ENABLE_LIBSINSP_E2E_TESTS "Enable libsinsp e2e tests" OFF)
option(BUILD_SHARED_LIBS "Build libscap and libsinsp as shared libraries" OFF)
option(ENABLE_VM_TESTS "Enable driver sanity tests" OFF)

if(${CMAKE_VERSION} VERSION_LESS "3.1.0" AND BUILD_SHARED_LIBS)
	# scap_engine_savefile uses target_sources
	message(FATAL_ERROR "Shared libraries requires CMake 3.1 or later.")
endif()

include(GNUInstallDirs)

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(versions)

# Libs version
if(NOT DEFINED FALCOSECURITY_LIBS_VERSION)
	get_libs_version(FALCOSECURITY_LIBS_VERSION)
endif()

message(STATUS "Libs version: ${FALCOSECURITY_LIBS_VERSION}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND USE_BUNDLED_DRIVER)
	# Driver version
	if(NOT DEFINED DRIVER_VERSION)
		get_drivers_version(DRIVER_VERSION)
	endif()

	message(STATUS "Driver version: ${DRIVER_VERSION}")

	add_subdirectory(driver ${PROJECT_BINARY_DIR}/driver)
endif()

if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
	set(CMAKE_BUILD_TYPE "Release")
endif()

set(LIBS_PACKAGE_NAME "falcosecurity")

include(CompilerFlags)

option(WITH_CHISEL "Include chisel implementation" OFF)

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS)
	include(gtest)
endif()

if (BUILD_SHARED_LIBS)
	get_shared_libs_versions(FALCOSECURITY_SHARED_LIBS_VERSION FALCOSECURITY_SHARED_LIBS_SOVERSION)
	message(STATUS "Shared library version: ${FALCOSECURITY_SHARED_LIBS_VERSION}")
	message(STATUS "Shared library soversion: ${FALCOSECURITY_SHARED_LIBS_SOVERSION}")
endif()

include(libscap)
include(libsinsp)

if(CREATE_TEST_TARGETS)
	# Add command to run all unit tests at once via the make system.
	# This is preferred vs using ctest's add_test because it will build
	# the code and output to stdout.
	add_custom_target(run-unit-tests
		COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
	)

	add_subdirectory(test/e2e)

	if(ENABLE_DRIVERS_TESTS)
		add_subdirectory(test/drivers)
	endif()

	if(ENABLE_LIBSCAP_TESTS)
		add_subdirectory(test/libscap)
	endif()

	if(ENABLE_LIBSINSP_E2E_TESTS)
		message(WARNING "LIBSINSP_E2E_TESTS are experimental!")
		add_subdirectory(test/libsinsp_e2e)
		add_subdirectory(test/libsinsp_e2e/resources)
	endif()

	if(ENABLE_VM_TESTS)
		add_subdirectory(test/vm)
	endif()

endif()
