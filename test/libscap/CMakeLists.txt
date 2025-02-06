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

message(STATUS "Libscap unit tests build enabled")

if(NOT DEFINED DRIVER_NAME)
	set(DRIVER_NAME "scap")
endif()

# Create a libscap_test_var.h file with some variables used by our tests for example the kmod path
# or the bpf path.
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/libscap_test_var.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/libscap_test_var.h"
)

set(LIBSCAP_TESTS_INCLUDE
	PRIVATE
	"${GTEST_INCLUDE}"
	"${CMAKE_CURRENT_SOURCE_DIR}" # for test helpers <helpers/...>
	"${LIBS_DIR}"
	"${LIBS_DIR}/userspace"
	"${PROJECT_BINARY_DIR}"
	"${CMAKE_CURRENT_BINARY_DIR}" # used to include `libscap_test_var.h`
)

# Needed by gtest
find_package(Threads)

set(LIBSCAP_TESTS_LIBRARIES "${GTEST_LIB}" "${GTEST_MAIN_LIB}" "${CMAKE_THREAD_LIBS_INIT}" scap)

set(LIBSCAP_TESTS_DEPENDENCIES gtest scap)

# Test suite asserting against pure userspace components
file(GLOB_RECURSE USERSPACE_TEST_SUITE "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/userspace/*.cpp"
	 "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/userspace/*.c"
)
set(LIBSCAP_TESTS_SOURCES ${USERSPACE_TEST_SUITE})

# Add _GNU_SOURCE definition for makedev and set C flags
add_definitions(-D_GNU_SOURCE)
set_source_files_properties(
	${CMAKE_CURRENT_SOURCE_DIR}/test_suites/userspace/linux/scap_fds_impl.c
	PROPERTIES COMPILE_FLAGS "-D_GNU_SOURCE -include sys/sysmacros.h" COMPILE_DEFINITIONS
																	  "HAVE_SYS_SYSMACROS_H"
)

# Add scap_engine_util for Linux tests
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND LIBSCAP_TESTS_LIBRARIES scap_engine_util)
endif()

# Helpers are not engine-specific so we always include them
file(GLOB_RECURSE LIBSCAP_TESTS_UTILS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/helpers/*cpp")
list(APPEND LIBSCAP_TESTS_SOURCES ${LIBSCAP_TESTS_UTILS_SOURCES})

# Linux specific tests
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	file(GLOB_RECURSE LINUX_TEST_SUITE
		 "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/userspace/linux/*.cpp"
	)
	list(APPEND LIBSCAP_TEST_SOURCES ${LINUX_TEST_SUITE})
endif()

# Engine-specific tests
if(BUILD_DRIVER)
	file(GLOB_RECURSE KMOD_TEST_SUITE "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/kmod/*.cpp")
	list(APPEND LIBSCAP_TESTS_SOURCES ${KMOD_TEST_SUITE})
	# Set `driver` target as a dependency
	list(APPEND LIBSCAP_TESTS_DEPENDENCIES driver)
endif()

if(BUILD_BPF)
	file(GLOB_RECURSE BPF_TEST_SUITE "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/bpf/*.cpp")
	list(APPEND LIBSCAP_TESTS_SOURCES ${BPF_TEST_SUITE})
	# Set `bpf` target as a dependency
	list(APPEND LIBSCAP_TESTS_DEPENDENCIES bpf)
endif()

if(BUILD_LIBSCAP_MODERN_BPF)
	file(GLOB_RECURSE MODERN_BPF_TEST_SUITE
		 "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/modern_bpf/*.cpp"
	)
	list(APPEND LIBSCAP_TESTS_SOURCES ${MODERN_BPF_TEST_SUITE})
endif()

if(BUILD_LIBSCAP_GVISOR)
	include(protobuf)
	file(GLOB_RECURSE GVISOR_TEST_SUITE
		 "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/gvisor/*.cpp"
	)
	list(APPEND LIBSCAP_TESTS_SOURCES ${GVISOR_TEST_SUITE})
	list(APPEND LIBSCAP_TESTS_INCLUDE "${CMAKE_BINARY_DIR}/libscap/engine/gvisor"
	)# Used for <pkg/sentry/...> includes
endif()

file(GLOB_RECURSE SAVEFILE_TEST_SUITE
	 "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/savefile/*.cpp"
)
list(APPEND LIBSCAP_TESTS_SOURCES ${SAVEFILE_TEST_SUITE})

# Summary logs
set(LIBSCAP_UNIT_TESTS_PREFIX "[LIBSCAP UNIT TESTS]")
message(STATUS "${LIBSCAP_UNIT_TESTS_PREFIX} LIBSCAP_TESTS_SOURCES: ${LIBSCAP_TESTS_SOURCES}")
message(STATUS "${LIBSCAP_UNIT_TESTS_PREFIX} LIBSCAP_TESTS_INCLUDE: ${LIBSCAP_TESTS_INCLUDE}")
message(STATUS "${LIBSCAP_UNIT_TESTS_PREFIX} LIBSCAP_TESTS_LIBRARIES: ${LIBSCAP_TESTS_LIBRARIES}")
message(
	STATUS "${LIBSCAP_UNIT_TESTS_PREFIX} LIBSCAP_TESTS_DEPENDENCIES: ${LIBSCAP_TESTS_DEPENDENCIES}"
)

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})
add_executable(libscap_test ${LIBSCAP_TESTS_SOURCES})
target_include_directories(libscap_test ${LIBSCAP_TESTS_INCLUDE})
target_link_libraries(libscap_test ${LIBSCAP_TESTS_LIBRARIES})
add_dependencies(libscap_test ${LIBSCAP_TESTS_DEPENDENCIES})
