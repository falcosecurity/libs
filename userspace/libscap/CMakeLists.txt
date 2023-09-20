#
# Copyright (C) 2022 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../common")

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

option(BUILD_LIBSCAP_MODERN_BPF "Enable modern bpf probe" OFF)

include(ExternalProject)

if(WIN32 OR NOT MINIMAL_BUILD)
	include(zlib)
endif()

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	endif()

	# do not remove this since when WITH_DRIVER is off
	if(NOT DEFINED DRIVER_NAME)
		set(DRIVER_NAME "scap")
	endif()

	string(REPLACE "-" "_" SCAP_KERNEL_MODULE_NAME "${DRIVER_NAME}")
	add_definitions(-DSCAP_KERNEL_MODULE_NAME="${SCAP_KERNEL_MODULE_NAME}")
endif()

if(NOT DEFINED SCAP_HOST_ROOT_ENV_VAR_NAME)
	set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")
endif()
add_definitions(-DSCAP_HOST_ROOT_ENV_VAR_NAME="${SCAP_HOST_ROOT_ENV_VAR_NAME}")

if(NOT DEFINED SCAP_HOSTNAME_ENV_VAR)
	set(SCAP_HOSTNAME_ENV_VAR "SCAP_HOSTNAME")
endif()
add_definitions(-DSCAP_HOSTNAME_ENV_VAR="${SCAP_HOSTNAME_ENV_VAR}")

if (DEFINED SCAP_BPF_PROGS_TAIL_CALLED_MAX)
	add_definitions(-DBPF_PROGS_TAIL_CALLED_MAX=${SCAP_BPF_PROGS_TAIL_CALLED_MAX})
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}) # temporary
    include_directories(${PROJECT_BINARY_DIR}/driver/src)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(scap
	scap.c
	scap_api_version.c
	scap_fds.c
	scap_savefile.c
	scap_platform.c
	scap_platform_api.c
	scap_procs.c
	scap_userlist.c
	scap_suppress.c)

set_scap_target_properties(scap)

add_library(scap_platform_util
	STATIC
	scap_iflist.c
	scap_proc_util.c)

if(NOT MINIMAL_BUILD)
target_link_libraries(scap
	"${ZLIB_LIB}")
endif()

add_library(scap_error STATIC strerror.c)

target_link_libraries(scap scap_error)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)
	include(FindMakedev)
endif()

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS)
	# Add engine only used for testing
	add_definitions(-DHAS_ENGINE_TEST_INPUT)
	add_subdirectory(engine/test_input)
	target_link_libraries(scap scap_engine_test_input)
endif()
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_subdirectory(linux)
	include_directories(linux)
	target_link_libraries(scap scap_platform)
elseif(EMSCRIPTEN)	
	include_directories(emscripten)
elseif(WIN32)
	include_directories(win32)
elseif(APPLE)
	include_directories(macos)
endif()

add_library(scap_event_schema
		STATIC
		scap_event.c
		ppm_sc_names.c
		../../driver/dynamic_params_table.c
		../../driver/event_table.c
		../../driver/flags_table.c
		../../driver/syscall_table64.c
		linux/scap_ppm_sc.c
        )

target_link_libraries(scap scap_event_schema)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_library(driver_event_schema
		STATIC
		../../driver/fillers_table.c)
	target_link_libraries(scap_event_schema driver_event_schema)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_library(scap_engine_util
		STATIC
		scap_engine_util.c
		ringbuffer/devset.c
		ringbuffer/ringbuffer.c)

	target_link_libraries(scap scap_engine_util)
endif()

add_definitions(-DHAS_ENGINE_NOOP)
add_subdirectory(engine/noop)
# don't link the noop engine to libscap directly,
# it's a helper library for other engines (it's completely useless on its own)

add_definitions(-DHAS_ENGINE_NODRIVER)
add_subdirectory(engine/nodriver)
target_link_libraries(scap scap_engine_nodriver)

add_definitions(-DHAS_ENGINE_SAVEFILE)
add_subdirectory(engine/savefile)
target_link_libraries(scap scap_engine_savefile)

add_definitions(-DHAS_ENGINE_SOURCE_PLUGIN)
add_subdirectory(engine/source_plugin)
target_link_libraries(scap scap_engine_source_plugin)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-DHAS_ENGINE_UDIG)
	add_subdirectory(engine/udig)
	target_link_libraries(scap scap_engine_udig)

	if (NOT MINIMAL_BUILD OR BUILD_LIBSCAP_MODERN_BPF)
		include(libelf)
	endif()

	if (NOT MINIMAL_BUILD)
		add_definitions(-DHAS_ENGINE_BPF)
		add_subdirectory(engine/bpf)
		target_link_libraries(scap scap_engine_bpf)
	endif()

	add_definitions(-DHAS_ENGINE_KMOD)
	add_subdirectory(engine/kmod)
	target_link_libraries(scap scap_engine_kmod)

	if(BUILD_LIBSCAP_MODERN_BPF)
		add_definitions(-DHAS_ENGINE_MODERN_BPF)
		add_subdirectory(engine/modern_bpf)
		target_link_libraries(scap scap_engine_modern_bpf)
	endif()

endif()

# gVisor is currently only supported on Linux x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" AND CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT MINIMAL_BUILD)
	option(BUILD_LIBSCAP_GVISOR "Build gVisor support" ON)
	if (BUILD_LIBSCAP_GVISOR)
		add_definitions(-DHAS_ENGINE_GVISOR)
		add_subdirectory(engine/gvisor)
		# The static and shared build differs here because a shared scap_engine_gvisor
		# will result in circular dependencies.
		if(BUILD_SHARED_LIBS)
			# We can move this to the gvisor CMakeFile when we use
			# CMake 3.13 or later.
			# https://cmake.org/cmake/help/latest/policy/CMP0079.html
			target_link_libraries(scap
				${CMAKE_THREAD_LIBS_INIT}
				${PROTOBUF_LIB}
				${JSONCPP_LIB}
			)
		else()
			target_link_libraries(scap scap_engine_gvisor)
		endif()
	endif()
endif()

if (BUILD_LIBSCAP_EXAMPLES)
	add_subdirectory(examples/01-open)
	add_subdirectory(examples/02-validatebuffer)
endif()
