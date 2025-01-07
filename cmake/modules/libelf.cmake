# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

include_guard()

option(USE_BUNDLED_LIBELF "Enable building of the bundled libelf" ${USE_BUNDLED_DEPS})
option(USE_SHARED_LIBELF "When not using bundled libelf, link it dynamically" ON)

if(TARGET elf)
	# we already have libelf
elseif(NOT USE_BUNDLED_LIBELF)
	find_path(LIBELF_INCLUDE elf.h PATH_SUFFIXES elf)
	if(BUILD_SHARED_LIBS OR USE_SHARED_LIBELF)
		set(LIBELF_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
	else()
		set(LIBELF_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
	endif()
	# Zig workaround: since it won't look up in /usr/lib/..., add an HINT
	if(CMAKE_C_COMPILER MATCHES "zig")
		find_library(
			LIBELF_LIB
			NAMES libelf${LIBELF_LIB_SUFFIX}
			HINTS /usr/lib/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/
		)
	else()
		find_library(LIBELF_LIB NAMES libelf${LIBELF_LIB_SUFFIX})
	endif()
	if(LIBELF_LIB)
		# Zig workaround: avoid include whole /usr/include because it would include also system
		# glibc headers breaking the build since we are targeting the build against our boostrapped
		# zig.
		if(CMAKE_C_COMPILER MATCHES "zig")
			message(STATUS "Enabling zig workaround for libelf")
			configure_file(${LIBELF_INCLUDE}/libelf.h libelf/libelf.h COPYONLY)
			configure_file(${LIBELF_INCLUDE}/elf.h libelf/elf.h COPYONLY)
			configure_file(${LIBELF_INCLUDE}/gelf.h libelf/gelf.h COPYONLY)
			set(LIBELF_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/libelf)
		endif()
		message(STATUS "Found LIBELF: include: ${LIBELF_INCLUDE}, lib: ${LIBELF_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system libelf")
	endif()

	if(BUILD_SHARED_LIBS OR USE_SHARED_LIBELF)
		add_library(elf SHARED IMPORTED)
	else()
		add_library(elf STATIC IMPORTED)
	endif()

	set_target_properties(elf PROPERTIES IMPORTED_LOCATION ${LIBELF_LIB})
	target_include_directories(elf INTERFACE ${LIBELF_INCLUDE})
else()
	include(FetchContent)
	FetchContent_Declare(
		libelf_elftoolchain
		URL https://github.com/falcosecurity/elftoolchain/releases/download/libelf-r4073-0/libelf-r4073-0.tar.gz
		URL_HASH SHA256=adfeb3033c23ca579902f2bce7d9ffeec662f97d3846bb74e57fb65d70f6f056
	)
	FetchContent_MakeAvailable(libelf_elftoolchain)
	get_target_property(LIBELF_INCLUDE elf INCLUDE_DIRECTORIES)

	message(STATUS "Using bundled libelf: include'${LIBELF_INCLUDE}'")
endif()
