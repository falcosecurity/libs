# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

option(USE_BUNDLED_UTHASH "Enable downloading of the bundled uthash library" ${USE_BUNDLED_DEPS})
set(UTHASH_DOWNLOAD_URL "https://raw.githubusercontent.com/troydhanson/uthash/v1.9.8/src/uthash.h")
set(UTHASH_DOWNLOAD_DIR "${LIBS_DIR}/userspace/libscap")

if(UTHASH_INCLUDE)
	# we already have uthash
elseif(NOT USE_BUNDLED_UTHASH)
	find_path(UTHASH_INCLUDE uthash.h)
	if(UTHASH_INCLUDE)
		message(STATUS "Found uthash: include: ${UTHASH_INCLUDE}")
	else()
		message(FATAL_ERROR "Couldn't find system uthash")
	endif()
else()
	set(UTHASH_SRC "${PROJECT_BINARY_DIR}/uthash-prefix/src/uthash/src")
	set(UTHASH_INCLUDE "${UTHASH_SRC}")

	message(STATUS "Using bundled uthash in '${UTHASH_SRC}'")

	ExternalProject_Add(uthash
			PREFIX "${PROJECT_BINARY_DIR}/uthash-prefix"
			URL "https://github.com/troydhanson/uthash/archive/refs/tags/v1.9.8.tar.gz"
			URL_HASH "SHA256=d9d123ce81c5d127442876fc3b12fab3ad632bee6aca685be7d461c08e24c046"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ""
			INSTALL_COMMAND "")
endif()

if(NOT TARGET uthash)
	add_custom_target(uthash)
endif()

include_directories("${UTHASH_INCLUDE}")
