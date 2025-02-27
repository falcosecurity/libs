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

set(CONTAINER_LIBRARY
	"${CMAKE_CURRENT_BINARY_DIR}/container_plugin-prefix/src/container_plugin/libcontainer.so"
)
if(NOT CONTAINER_VERSION)
	set(CONTAINER_VERSION "0.1.0-rc3")
endif()
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	if(NOT CONTAINER_HASH)
		set(CONTAINER_HASH "059e8a1f7018d7ead97abc46566a82d8250c03e520d6e8858828bd07c3cb5af7")
	endif()
else() # arm64
	if(NOT CONTAINER_HASH)
		set(CONTAINER_HASH "5b7892ac01ed109f3da86a3b1603d14d41363755f2362d82946df512e88768cf")
	endif()
endif()
if(NOT TARGET container_plugin)
	message(STATUS "Fetching container plugin ${CONTAINER_VERSION} in '${CONTAINER_LIBRARY}'")
	ExternalProject_Add(
		container_plugin
		URL "https://github.com/FedeDP/container_plugin/releases/download/${CONTAINER_VERSION}/container-${CONTAINER_VERSION}-linux-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
		URL_HASH "SHA256=${CONTAINER_HASH}"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)
endif()
