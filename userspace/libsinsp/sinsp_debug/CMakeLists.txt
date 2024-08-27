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

add_executable(sinsp-debug
	sinsp_debug.cpp
)

target_link_libraries(sinsp-debug
	PRIVATE
	sinsp
)

if (EMSCRIPTEN)
	target_compile_options(sinsp-debug PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-debug PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(sinsp-debug PRIVATE "-sALLOW_MEMORY_GROWTH=1")
	target_link_options(sinsp-debug PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
	# note(jasondellaluce): since we run tests with node, we need to add this
	# for reading from local capture files.
	target_link_options(sinsp-debug PRIVATE "-sNODERAWFS=1")
endif()

if (APPLE AND NOT MINIMAL_BUILD)
	# Needed when linking libcurl
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Foundation -framework SystemConfiguration")
endif()
