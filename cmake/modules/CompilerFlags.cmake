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

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

option(ENABLE_PIC "Build position independent libraries and executables" ${BUILD_SHARED_LIBS})
if(ENABLE_PIC)
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# NOTE: do not add `add_definition` in this file because consumers project won't import it.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

set(FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS "")
set(FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS "")

if(NOT MSVC)

	set(FALCOSECURITY_LIBS_COMMON_FLAGS "-Wall -ggdb")
	set(FALCOSECURITY_LIBS_DEBUG_FLAGS "-Og -D_DEBUG")
	set(FALCOSECURITY_LIBS_RELEASE_FLAGS "-O3 -fno-strict-aliasing -DNDEBUG")
	set(FALCOSECURITY_LIBS_COVERAGE_FLAGS "-O0 -fprofile-arcs -ftest-coverage")

	if(MINIMAL_BUILD)
	  set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -DMINIMAL_BUILD")
	endif()

	if(MUSL_OPTIMIZED_BUILD)
		set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -static -Os")
	endif()

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-sign-compare -Wno-implicit-fallthrough -Wno-format-truncation")
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
			# Clang needs these for suppressing these warnings:
			#   - C++20 array designators used with C++17
			#   - C99 array designators used in C++
			#   - avoid complaining about the option above `-Wno-format-truncation`
			set(CMAKE_SUPPRESSED_WARNINGS "${CMAKE_SUPPRESSED_WARNINGS} -Wno-c++20-designator -Wno-c99-designator -Wno-unknown-warning-option")
		endif()
		set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -Werror -Wextra ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	if(USE_ASAN)
		set(FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS "${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS};-fsanitize=address")
		set(FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS "${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS};-fsanitize=address;-lpthread")
	endif()

	if(USE_UBSAN)
		set(FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS "${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS};-fsanitize=undefined")
		set(FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS "${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS};-fsanitize=undefined")
		if(UBSAN_HALT_ON_ERROR)
			set(FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS "${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS};-fno-sanitize-recover=undefined")
		endif()
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FALCOSECURITY_LIBS_COMMON_FLAGS}")
	# we need also `-std=c++17` here beacuse `set(CMAKE_CXX_STANDARD 17)` is not enough to enforce c++17
	# with some Cmake versions: https://github.com/falcosecurity/libs/pull/950
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FALCOSECURITY_LIBS_COMMON_FLAGS} -std=c++17")

	set(CMAKE_C_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")

	set(CMAKE_C_FLAGS_COVERAGE "${FALCOSECURITY_LIBS_COVERAGE_FLAGS}")
	set(CMAKE_CXX_FLAGS_COVERAGE "${FALCOSECURITY_LIBS_COVERAGE_FLAGS}")

	add_definitions(-D__STDC_FORMAT_MACROS)

else() # MSVC
	set(MINIMAL_BUILD ON)

	set(FALCOSECURITY_LIBS_COMMON_FLAGS "-D_CRT_SECURE_NO_WARNINGS -DWIN32 -DMINIMAL_BUILD /EHsc /W3 /Zi /std:c++17")
	if(CMAKE_VERSION VERSION_LESS 3.15.0)
		set(FALCOSECURITY_LIBS_DEBUG_FLAGS "/MTd /Od")
		set(FALCOSECURITY_LIBS_RELEASE_FLAGS "/MT")
	else()
		# /MT vs /MD should be determined via CMAKE_MSVC_RUNTIME_LIBRARY
		set(FALCOSECURITY_LIBS_DEBUG_FLAGS "/Od")
	endif()

	set(CMAKE_C_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")

	set(CMAKE_C_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")

	add_compile_definitions(
		_HAS_STD_BYTE=0
		WIN32_LEAN_AND_MEAN
	)
endif()
