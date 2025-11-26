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

# Using `STATIC` is not enough on Windows builds, so we directly create object files that will be
# included inside `scap_engine_savefile` library
add_library(scap_savefile_converter OBJECT converter.cpp table.cpp)

find_package(Uthash REQUIRED)
target_include_directories(
	scap_savefile_converter
	PRIVATE ${LIBS_DIR} ${LIBS_DIR}/userspace ${LIBS_DIR}/userspace/libscap/engine/savefile
			${UTHASH_INCLUDE_DIRS}
)
target_link_libraries(scap_savefile_converter PRIVATE scap_error)
