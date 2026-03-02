# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
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

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	message(FATAL_ERROR "ENABLE_LIBSCAP_FUZZERS requires clang/libFuzzer (set CMAKE_CXX_COMPILER=clang++).")
endif()

add_executable(fuzz_scap_event_decode fuzz_scap_event_decode.cc)
target_include_directories(
	fuzz_scap_event_decode
	PRIVATE "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/userspace" "${PROJECT_BINARY_DIR}"
)
target_link_libraries(fuzz_scap_event_decode PRIVATE scap)
add_dependencies(fuzz_scap_event_decode scap)
target_compile_definitions(fuzz_scap_event_decode PRIVATE -D_GNU_SOURCE)

# Build a standalone libFuzzer binary for local runs.
target_compile_options(
	fuzz_scap_event_decode
	PRIVATE ${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS} -fsanitize=fuzzer-no-link
)
target_link_options(
	fuzz_scap_event_decode
	PRIVATE ${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS} -fsanitize=fuzzer
)
