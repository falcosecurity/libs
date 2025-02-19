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
set(CONTAINER_VERSION "0.1.0-rc1")
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(CONTAINER_HASH "74cbbc63414c18db3897b729894968be8554720250d11bb47ef5450314d554f6")
	set(CONTAINER_ARCH "amd64")
else() # arm64
	set(CONTAINER_HASH "dec90575c16dc076f9cad0e22b76e4344ed50dd14fa5696825b6fb4aa51d3a91")
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
