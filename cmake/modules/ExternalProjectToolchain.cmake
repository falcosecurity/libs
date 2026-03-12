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

	if(DEFINED CMAKE_C_COMPILER AND NOT "${CMAKE_C_COMPILER}" STREQUAL "")
		list(APPEND args "CC=${CMAKE_C_COMPILER}")
	endif()
	if(DEFINED CMAKE_CXX_COMPILER AND NOT "${CMAKE_CXX_COMPILER}" STREQUAL "")
		list(APPEND args "CXX=${CMAKE_CXX_COMPILER}")
	endif()
	if(DEFINED CMAKE_AR AND NOT "${CMAKE_AR}" STREQUAL "")
		list(APPEND args "AR=${CMAKE_AR}")
	endif()
	if(DEFINED CMAKE_RANLIB AND NOT "${CMAKE_RANLIB}" STREQUAL "")
		list(APPEND args "RANLIB=${CMAKE_RANLIB}")
	endif()
	if(DEFINED CMAKE_STRIP AND NOT "${CMAKE_STRIP}" STREQUAL "")
		list(APPEND args "STRIP=${CMAKE_STRIP}")
	endif()
	if(DEFINED CMAKE_NM AND NOT "${CMAKE_NM}" STREQUAL "")
		list(APPEND args "NM=${CMAKE_NM}")
	endif()
	if(DEFINED CMAKE_LINKER AND NOT "${CMAKE_LINKER}" STREQUAL "")
		list(APPEND args "LD=${CMAKE_LINKER}")
	endif()

	if(DEFINED FALCOSECURITY_EXTERNAL_PROJECT_ENV)
		list(APPEND args ${FALCOSECURITY_EXTERNAL_PROJECT_ENV})
	endif()

	set(${out_var}
		${args}
		PARENT_SCOPE
	)
endfunction()
