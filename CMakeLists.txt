#
# Copyright (C) 2022 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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

cmake_minimum_required(VERSION 2.8.5)

project(falcosecurity-libs)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)
option(MINIMAL_BUILD "Produce a minimal build with only the essential features (no eBPF probe driver, no kubernetes, no mesos, no marathon and no container metadata)" OFF)
option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)
option(USE_BUNDLED_DRIVER "Use the driver/ subdirectory in the build process (only available in Linux)" ON)

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

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(LIBS_PACKAGE_NAME "falcosecurity")

include(CompilerFlags)

option(WITH_CHISEL "Include chisel implementation" OFF)

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS AND NOT WIN32)
	include(gtest)
endif()

include(libscap)
include(libsinsp)

if(CREATE_TEST_TARGETS AND NOT WIN32)
	# Add command to run all unit tests at once via the make system.
	# This is preferred vs using ctest's add_test because it will build
	# the code and output to stdout.
	add_custom_target(run-unit-tests
		COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
		COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libscap
	)

	add_subdirectory(test/e2e)
endif()
