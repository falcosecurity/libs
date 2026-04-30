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

include_guard()

function(falcosecurity_external_project_append_cache_arg args_var var type)
	if(DEFINED ${var} AND NOT "${${var}}" STREQUAL "")
		list(APPEND ${args_var} "-D${var}:${type}=${${var}}")
		set(${args_var}
			"${${args_var}}"
			PARENT_SCOPE
		)
	endif()
endfunction()

function(falcosecurity_external_project_cache_args out_var)
	set(args)

	falcosecurity_external_project_append_cache_arg(args CMAKE_SYSTEM_NAME STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_SYSTEM_PROCESSOR STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_BUILD_TYPE STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_TOOLCHAIN_FILE FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_SYSROOT PATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_C_COMPILER FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_CXX_COMPILER FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_ASM_COMPILER FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_C_COMPILER_TARGET STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_CXX_COMPILER_TARGET STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_AR FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_RANLIB FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_STRIP FILEPATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_FIND_ROOT_PATH PATH)
	falcosecurity_external_project_append_cache_arg(args CMAKE_FIND_ROOT_PATH_MODE_PROGRAM STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_FIND_ROOT_PATH_MODE_LIBRARY STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_FIND_ROOT_PATH_MODE_INCLUDE STRING)
	falcosecurity_external_project_append_cache_arg(args CMAKE_FIND_ROOT_PATH_MODE_PACKAGE STRING)

	if(DEFINED FALCOSECURITY_EXTERNAL_PROJECT_CMAKE_CACHE_ARGS)
		list(APPEND args ${FALCOSECURITY_EXTERNAL_PROJECT_CMAKE_CACHE_ARGS})
	endif()

	set(${out_var}
		${args}
		PARENT_SCOPE
	)
endfunction()

function(falcosecurity_external_project_env out_var)
	set(args env)

	# Build compiler env vars: compiler + optional subcommand (_ARG1) + optional -target flag. CMake
	# auto-populates CMAKE_*_COMPILER_ARG1 from list-form CMAKE_*_COMPILER (e.g. "zig" "cc"). The
	# -target flag goes in CC/CXX (not CFLAGS) to avoid overriding the project's own CFLAGS, which
	# would cause Zig to default to -O0 and emit UBSan instrumentation.
	set(_target_flag "")
	if(DEFINED CMAKE_C_COMPILER_TARGET AND NOT "${CMAKE_C_COMPILER_TARGET}" STREQUAL "")
		set(_target_flag " -target ${CMAKE_C_COMPILER_TARGET}")
	endif()

	macro(_falcosecurity_append_compiler_env env_var cmake_compiler cmake_arg1)
		if(DEFINED ${cmake_compiler} AND NOT "${${cmake_compiler}}" STREQUAL "")
			set(_cmd "${${cmake_compiler}}")
			if(DEFINED ${cmake_arg1} AND NOT "${${cmake_arg1}}" STREQUAL "")
				string(STRIP "${${cmake_arg1}}" _stripped_arg1)
				string(APPEND _cmd " ${_stripped_arg1}")
			endif()
			string(APPEND _cmd "${_target_flag}")
			list(APPEND args "${env_var}=${_cmd}")
		endif()
	endmacro()

	_falcosecurity_append_compiler_env(CC CMAKE_C_COMPILER CMAKE_C_COMPILER_ARG1)
	_falcosecurity_append_compiler_env(CXX CMAKE_CXX_COMPILER CMAKE_CXX_COMPILER_ARG1)

	macro(_falcosecurity_append_env env_var cmake_var)
		if(DEFINED ${cmake_var} AND NOT "${${cmake_var}}" STREQUAL "")
			list(APPEND args "${env_var}=${${cmake_var}}")
		endif()
	endmacro()

	# AR/RANLIB: prefer the environment variable (supports multi-tool commands like "zig ar"), fall
	# back to the CMAKE_* variable for standard toolchains.
	macro(_falcosecurity_append_tool_env env_var env_name cmake_var)
		if(NOT "$ENV{${env_name}}" STREQUAL "")
			list(APPEND args "${env_var}=$ENV{${env_name}}")
		elseif(DEFINED ${cmake_var} AND NOT "${${cmake_var}}" STREQUAL "")
			list(APPEND args "${env_var}=${${cmake_var}}")
		endif()
	endmacro()

	_falcosecurity_append_tool_env(AR AR CMAKE_AR)
	_falcosecurity_append_tool_env(RANLIB RANLIB CMAKE_RANLIB)

	_falcosecurity_append_env(STRIP CMAKE_STRIP)
	_falcosecurity_append_env(NM CMAKE_NM)
	_falcosecurity_append_env(LD CMAKE_LINKER)

	if(DEFINED FALCOSECURITY_EXTERNAL_PROJECT_ENV)
		list(APPEND args ${FALCOSECURITY_EXTERNAL_PROJECT_ENV})
	endif()

	set(${out_var}
		${args}
		PARENT_SCOPE
	)
endfunction()

# Autotools --host flag for cross-compilation. Tells autotools configure scripts not to try running
# compiled test programs.
if(CMAKE_CROSSCOMPILING AND NOT "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL
							"${CMAKE_HOST_SYSTEM_PROCESSOR}"
)
	set(FALCOSECURITY_AUTOTOOLS_HOST_FLAG --host=${CMAKE_SYSTEM_PROCESSOR}-linux-gnu)
else()
	set(FALCOSECURITY_AUTOTOOLS_HOST_FLAG "")
endif()
