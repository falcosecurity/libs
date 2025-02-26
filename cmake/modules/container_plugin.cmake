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

set(CONTAINER_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/container_plugin-prefix/src/libcontainer.so")
if(NOT CONTAINER_VERSION)
	set(CONTAINER_VERSION "0.1.0-rc2")
endif()
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	if(NOT CONTAINER_HASH)
		set(CONTAINER_HASH "d7b7a1d35dcefb45cd9737ab4a3d6e259522637a009e3d6cb0ff729ab1c34685")
	endif()
	set(CONTAINER_ARCH "amd64")
else() # arm64
	if(NOT CONTAINER_HASH)
		set(CONTAINER_HASH "fd569320a17c22310c55e820ae26b413ba0404d476bfb90a42be67b6be9d939b")
	endif()
	set(CONTAINER_ARCH "arm64")
endif()
if(NOT TARGET container_plugin)
	message(STATUS "Fetching container plugin ${CONTAINER_VERSION} in '${CONTAINER_LIBRARY}'")
	ExternalProject_Add(
		container_plugin
		URL "https://github.com/FedeDP/container_plugin/releases/download/${CONTAINER_VERSION}/libcontainer_${CONTAINER_ARCH}.so"
		URL_HASH "SHA256=${CONTAINER_HASH}"
		DOWNLOAD_NAME "libcontainer.so"
		DOWNLOAD_NO_EXTRACT 1
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)
endif()
