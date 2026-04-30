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

# Zig cross-compilation toolchain for Linux.
#
# Configuration via environment variables: ZIG          - path to the zig executable (falls back to
# PATH lookup) ZIG_TARGET   - Zig target triple, e.g. "aarch64-linux-gnu.2.17" (required)
#
# Compilers use list syntax (e.g. "zig" "cc") -- CMake auto-splits into CMAKE_C_COMPILER +
# CMAKE_C_COMPILER_ARG1, avoiding FILEPATH truncation in nested -D flags.
#
# CMAKE_AR / CMAKE_RANLIB must be a single executable path (CMake validates them as FILEPATH and
# nested projects like yaml-cpp use them directly without custom archive rules). The *_ARCHIVE_*
# rules embed the subcommand so CMake invokes "zig ar qc ..." / "zig ranlib ...". ENV{AR} /
# ENV{RANLIB} hold the full shell command ("zig ar", "zig ranlib") so ExternalProjectToolchain can
# forward them to autotools builds.

# -- Target triple -----------------------------------------------------------

if(NOT DEFINED TARGET_TRIPLE)
	if(NOT "$ENV{ZIG_TARGET}" STREQUAL "")
		set(TARGET_TRIPLE "$ENV{ZIG_TARGET}")
	elseif(DEFINED CMAKE_C_COMPILER_TARGET AND NOT "${CMAKE_C_COMPILER_TARGET}" STREQUAL "")
		set(TARGET_TRIPLE "${CMAKE_C_COMPILER_TARGET}")
	else()
		message(
			FATAL_ERROR "ZIG_TARGET environment variable is required (e.g. aarch64-linux-gnu.2.17)"
		)
	endif()
endif()

string(REPLACE "-" ";" _triple_parts "${TARGET_TRIPLE}")
list(GET _triple_parts 0 _arch)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR "${_arch}")

# When target arch matches the host, the output is natively runnable.
cmake_host_system_information(RESULT _host_arch QUERY OS_PLATFORM)
if("${_arch}" STREQUAL "${_host_arch}")
	set(CMAKE_CROSSCOMPILING FALSE)
endif()

# -- Zig executable ----------------------------------------------------------

if(NOT DEFINED ZIG_EXECUTABLE)
	if(NOT "$ENV{ZIG}" STREQUAL "")
		set(ZIG_EXECUTABLE "$ENV{ZIG}")
	elseif(DEFINED CMAKE_C_COMPILER AND EXISTS "${CMAKE_C_COMPILER}")
		set(ZIG_EXECUTABLE "${CMAKE_C_COMPILER}")
	else()
		find_program(ZIG_EXECUTABLE zig)
		if(NOT ZIG_EXECUTABLE)
			message(
				FATAL_ERROR "Zig not found. Set the ZIG environment variable or add zig to PATH."
			)
		endif()
	endif()
endif()

list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ZIG_EXECUTABLE TARGET_TRIPLE)

# -- Compilers ---------------------------------------------------------------

set(CMAKE_C_COMPILER "${ZIG_EXECUTABLE}" cc)
set(CMAKE_CXX_COMPILER "${ZIG_EXECUTABLE}" c++)

# -- Archiver / ranlib -------------------------------------------------------

set(CMAKE_AR "${ZIG_EXECUTABLE}")
set(ENV{AR} "${ZIG_EXECUTABLE} ar")
set(CMAKE_RANLIB "${ZIG_EXECUTABLE}")
set(ENV{RANLIB} "${ZIG_EXECUTABLE} ranlib")
foreach(L IN ITEMS C CXX)
	set(CMAKE_${L}_ARCHIVE_CREATE "<CMAKE_AR> ar qc <TARGET> <LINK_FLAGS> <OBJECTS>")
	set(CMAKE_${L}_ARCHIVE_APPEND "<CMAKE_AR> ar q <TARGET> <LINK_FLAGS> <OBJECTS>")
	set(CMAKE_${L}_ARCHIVE_FINISH "<CMAKE_RANLIB> ranlib <TARGET>")
endforeach()

# -- Target flags ------------------------------------------------------------

set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_C_FLAGS_INIT "-target ${TARGET_TRIPLE} -mcpu=baseline")
set(CMAKE_CXX_FLAGS_INIT "-target ${TARGET_TRIPLE} -mcpu=baseline")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-target ${TARGET_TRIPLE}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-target ${TARGET_TRIPLE}")
