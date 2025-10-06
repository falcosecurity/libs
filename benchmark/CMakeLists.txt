# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
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

message(STATUS "Benchmarks enabled")

include(googleBenchmark)

set(BENCHMARK_SOURCES ./main.cpp)
set(BENCHMARK_DEPENDENCIES sinsp)
set(BENCHMARK_LIBRARIES benchmark::benchmark sinsp)
set(BENCHMARK_INCLUDE PRIVATE "${LIBSINSP_INCLUDE_DIRS}")

file(GLOB_RECURSE SINSP_SUITE CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libsinsp/*.cpp")
list(APPEND BENCHMARK_SOURCES ${SINSP_SUITE})

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})
add_executable(bench ${BENCHMARK_SOURCES})
target_link_libraries(bench ${BENCHMARK_LIBRARIES})
target_include_directories(bench ${BENCHMARK_INCLUDE})
add_dependencies(bench ${BENCHMARK_DEPENDENCIES})
