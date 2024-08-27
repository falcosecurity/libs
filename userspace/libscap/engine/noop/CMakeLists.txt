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
add_library(scap_engine_noop STATIC noop.c)

target_include_directories(scap_engine_noop
PUBLIC
    $<BUILD_INTERFACE:${LIBS_DIR}>
    $<BUILD_INTERFACE:${LIBS_DIR}/userspace>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_dependencies(scap_engine_noop uthash)
