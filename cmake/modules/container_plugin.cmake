# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
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

include(ExternalProject)

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

set(CONTAINER_LIBRARY
	"${CMAKE_CURRENT_BINARY_DIR}/container_plugin-prefix/src/container_plugin/libcontainer.so"
)

if(NOT CONTAINER_VERSION)
	set(CONTAINER_VERSION "0.7.2")
endif()
if(NOT CONTAINER_HASH)
	if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
		set(CONTAINER_HASH "3327d5b085c3e0988d5937ef758a71d99bf74edadd58b8ff238013b0d7998ba3")
	else() # arm64
		set(CONTAINER_HASH "8475a4e89e7dbdff6bcc8136bf253c4619b49f332fbf0c2d5a1577afd6b9ec22")
	endif()
endif()
if(NOT TARGET container_plugin)
	message(STATUS "Fetching container plugin ${CONTAINER_VERSION} in '${CONTAINER_LIBRARY}'")
	ExternalProject_Add(
		container_plugin
		URL "https://download.falco.org/plugins/stable/container-${CONTAINER_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
		URL_HASH "SHA256=${CONTAINER_HASH}"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)
endif()
