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

#
# cxxopts (https://github.com/jarro2783/cxxopts)
#

option(USE_BUNDLED_CXXOPTS "Enable building of the bundled cxxopts" ${USE_BUNDLED_DEPS})

if(CXXOPTS_INCLUDE_DIR)
	# we already have cxxopts
elseif(NOT USE_BUNDLED_CXXOPTS)
	find_package(cxxopts CONFIG)
	if(CXXOPTS_INCLUDE_DIR)
		get_target_property(CXXOPTS_INCLUDE_DIR cxxopts::cxxopts INTERFACE_INCLUDE_DIRECTORIES)
	else()
		# Was it manually installed?
		find_path(CXXOPTS_INCLUDE_DIR cxxopts.hpp)
		if(CXXOPTS_INCLUDE_DIR)
			message(STATUS "Found cxxopts: include: ${CXXOPTS_INCLUDE_DIR}")
		else()
			message(FATAL_ERROR "Couldn't find system cxxopts")
		endif()
	endif()
else()
	set(CXXOPTS_SRC "${CMAKE_CURRENT_BINARY_DIR}/cxxopts-prefix/src/cxxopts/")
	set(CXXOPTS_INCLUDE_DIR "${CXXOPTS_SRC}/include")
	file(MAKE_DIRECTORY "${CXXOPTS_INCLUDE_DIR}") # needed to make target_include_directories() work

	message(STATUS "Using bundled cxxopts in ${CXXOPTS_SRC}")

	ExternalProject_Add(
		cxxopts
		URL "https://github.com/jarro2783/cxxopts/archive/refs/tags/v3.3.1.tar.gz"
		URL_HASH "SHA256=3bfc70542c521d4b55a46429d808178916a579b28d048bd8c727ee76c39e2072"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)
endif()

if(NOT TARGET cxxopts)
	add_custom_target(cxxopts)
endif()
