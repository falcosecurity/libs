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

add_executable(extract_scap_events extract_scap_events.cc)

set_target_properties(
	extract_scap_events
	PROPERTIES CXX_STANDARD 17
			   CXX_STANDARD_REQUIRED ON
			   CXX_EXTENSIONS OFF
)

target_include_directories(
	extract_scap_events PRIVATE "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/userspace"
								"${PROJECT_BINARY_DIR}"
)

target_compile_definitions(extract_scap_events PRIVATE _GNU_SOURCE)

target_compile_options(extract_scap_events PRIVATE ${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})

target_link_libraries(extract_scap_events PRIVATE scap)

target_link_options(extract_scap_events PRIVATE ${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})

add_dependencies(extract_scap_events scap)
