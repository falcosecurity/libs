#
# Copyright (C) 2021 The Falco Authors.
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
# run cmake in-tree. (see Issue 71: https://github.com/draios/sysdig/issues/71)
if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
	message(FATAL_ERROR
		"Looks like you are trying to run cmake from the base sysdig source directory.\n"
		"** RUNNING CMAKE FROM THE BASE SYSDIG DIRECTORY WILL NOT WORK **\n"
		"To Fix:\n"
		" 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
		" 2. Create a build directory from here. ex: mkdir build\n"
		" 3. cd into that directory. ex: cd build\n"
		" 4. Run cmake from the build directory. ex: cmake ..\n"
		" 5. Run make from the build directory. ex: make\n"
		"Full paste-able example:\n"
		"( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )\n"
		"The following wiki page has more information on manually building sysdig: http://bit.ly/1oJ84UI")
endif()

cmake_minimum_required(VERSION 2.8.2)

project(sysdig)

option(MINIMAL_BUILD "Produce a minimal sysdig binary with only the essential features (no eBPF probe driver, no kubernetes, no mesos, no marathon and no container metadata)" OFF)
option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(NOT DEFINED SYSDIG_VERSION)
	set(SYSDIG_VERSION "0.1.1dev")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(PACKAGE_NAME "sysdig")

include(CompilerFlags)

option(WITH_CHISEL "Include chisel implementation" OFF)

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

include(libscap)
include(libsinsp)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add command to run all unit tests at once via the make system.
		# This is preferred vs using ctest's add_test because it will build
		# the code and output to stdout.
		add_custom_target(run-unit-tests
			COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
		)
endif()
