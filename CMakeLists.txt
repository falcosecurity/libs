#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
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

if(NOT DEFINED DIR_ETC)
	set(DIR_ETC "${CMAKE_INSTALL_PREFIX}/etc")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(PACKAGE_NAME "sysdig")

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
	set(CMD_MAKE gmake)
else()
	set(CMD_MAKE make)
endif()

if(NOT WIN32)

	set(SYSDIG_COMMON_FLAGS "-Wall -ggdb")
	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")
	set(SYSDIG_RELEASE_FLAGS "-O3 -fno-strict-aliasing -DNDEBUG")

	if(MINIMAL_BUILD)
	  set(SYSDIG_COMMON_FLAGS "${SYSDIG_COMMON_FLAGS} -DMINIMAL_BUILD")
	endif()

	if(MUSL_OPTIMIZED_BUILD)
		set(SYSDIG_COMMON_FLAGS "${SYSDIG_COMMON_FLAGS} -static -Os")
	endif()

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
		set(SYSDIG_COMMON_FLAGS "${SYSDIG_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SYSDIG_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SYSDIG_COMMON_FLAGS} -std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_RELEASE_FLAGS}")

	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS}")
	endif()

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_definitions(-DHAS_CAPTURE)
	endif()

else()
	set(MINIMAL_BUILD ON)

	set(SYSDIG_COMMON_FLAGS "-D_CRT_SECURE_NO_WARNINGS -DWIN32 -DMINIMAL_BUILD /EHsc /W3 /Zi")
	set(SYSDIG_DEBUG_FLAGS "/MTd /Od")
	set(SYSDIG_RELEASE_FLAGS "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_COMMON_FLAGS}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_RELEASE_FLAGS}")

	add_definitions(-DHAS_CAPTURE)
	
endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

option(WITH_CHISEL "Include chisel implementation" OFF)

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add command to run all unit tests at once via the make system.
		# This is preferred vs using ctest's add_test because it will build
		# the code and output to stdout.
		add_custom_target(run-unit-tests
			COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
		)
endif()
