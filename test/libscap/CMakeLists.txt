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

message(STATUS "Libscap unit tests build enabled")

# find_package(Threads)

set(LIBSCAP_TESTS_SOURCES "")

set(LIBSCAP_TESTS_INCLUDE
  PRIVATE
  "${GTEST_INCLUDE}"
  "${CMAKE_CURRENT_SOURCE_DIR}" # for test helpers <helpers/...>
  "${CMAKE_SOURCE_DIR}/userspace/libscap" # this is for libscap includes
)

set(LIBSCAP_TESTS_LIBRARIES
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	# "${CMAKE_THREAD_LIBS_INIT}"
	scap
)

set(LIBSCAP_TESTS_DEPENDENCIES
	gtest
	scap
)

# Add `gcov` to needed libraries
if (CMAKE_BUILD_TYPE STREQUAL "Coverage")
	list(APPEND LIBSCAP_TESTS_LIBRARIES gcov)
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
	file(GLOB_RECURSE MODERN_BPF_TEST_SUITE "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/modern_bpf/*.cpp")
	list(APPEND LIBSCAP_TESTS_SOURCES ${MODERN_BPF_TEST_SUITE})
endif()

if(BUILD_LIBSCAP_GVISOR)
	include(protobuf)
	file(GLOB_RECURSE GVISOR_TEST_SUITE "${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/gvisor/*.cpp")
	list(APPEND LIBSCAP_TESTS_SOURCES ${GVISOR_TEST_SUITE})
	list(APPEND LIBSCAP_TESTS_INCLUDE "${CMAKE_BINARY_DIR}/libscap")

	# include_directories(${CMAKE_CURRENT_BINARY_DIR}/..)
	# include_directories(../engine/gvisor)
	# include_directories(${CMAKE_CURRENT_BINARY_DIR}/../engine/gvisor)
endif()

# Helpers are not engine-specific so we always include them
file(GLOB_RECURSE LIBSCAP_TESTS_UTILS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/helpers/*cpp")
list(APPEND LIBSCAP_TESTS_SOURCES ${LIBSCAP_TESTS_UTILS_SOURCES})

add_executable(libscap_test ${LIBSCAP_TESTS_SOURCES})
target_include_directories(libscap_test ${LIBSCAP_TESTS_INCLUDE})
target_link_libraries(libscap_test ${LIBSCAP_TESTS_LIBRARIES})
add_dependencies(libscap_test ${LIBSCAP_TESTS_DEPENDENCIES})

# ## Probably we can remove these
# add_custom_target(run-libscap_test
# 	DEPENDS ${RUN_LIBSCAP_TESTS_DEPENDENCIES}
# 	COMMAND libscap_test
# )
