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
message(STATUS "Build modern BPF engine")
option(USE_BUNDLED_MODERN_BPF "use bundled modern BPF" ON)
set(MODERN_BPF_LOG_PREFIX "[MODERN BPF]")

# Include `libbpf` library.
include(libbpf RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
  message(FATAL_ERROR "problem with libbpf.cmake in ${CMAKE_MODULE_PATH}")
endif()

# This will be the name of the final `bpf.o` file. We put it here this way
# we can log it even if `USE_BUNDLED_MODERN_BPF` is `OFF`
set(UNIQUE_BPF_O_FILE_NAME bpf_probe)

# This must be a dir because we use it as an include path
if(NOT MODERN_BPF_SKEL_DIR)
  # Directory in which the BPF skeleton will be built
  set(MODERN_BPF_SKEL_DIR "${CMAKE_BINARY_DIR}/skel_dir")
  file(MAKE_DIRECTORY ${MODERN_BPF_SKEL_DIR})
  # Build the BPF skeleton as custom target.
  add_subdirectory(${LIBS_DIR}/driver/modern_bpf ${CMAKE_BINARY_DIR}/driver/modern_bpf)
else()
  set(USE_BUNDLED_MODERN_BPF OFF)
  # If it is a relative path we convert it to an absolute one relative to the root source directory.
  get_filename_component(MODERN_BPF_SKEL_DIR "${MODERN_BPF_SKEL_DIR}" REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
endif()
message(STATUS "${MODERN_BPF_LOG_PREFIX} USE_BUNDLED_MODERN_BPF: ${USE_BUNDLED_MODERN_BPF}, using skeleton dir: ${MODERN_BPF_SKEL_DIR}")
message(STATUS "${MODERN_BPF_LOG_PREFIX} full skeleton path: ${MODERN_BPF_SKEL_DIR}/${UNIQUE_BPF_O_FILE_NAME}.skel.h")

# Build `libpman` library.
add_subdirectory(${LIBS_DIR}/userspace/libpman ${CMAKE_BINARY_DIR}/libpman)

add_library(scap_engine_modern_bpf
	scap_modern_bpf.c
)

target_link_libraries(scap_engine_modern_bpf
PRIVATE
    pman
    scap_engine_util
    scap_engine_noop
)

set_scap_target_properties(scap_engine_modern_bpf)
