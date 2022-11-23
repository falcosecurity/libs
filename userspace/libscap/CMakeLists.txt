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

if(NOT MSVC)
	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_definitions(-DHAS_CAPTURE)
	endif()
else() # MSVC
	# todo(leogr): this should be removed - double check
	add_definitions(-DHAS_CAPTURE)
endif()

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

if (DEFINED SCAP_BPF_PROGS_MAX)
	add_definitions(-DBPF_PROGS_MAX=${SCAP_BPF_PROGS_MAX})
endif()

if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

list(APPEND targetfiles
	scap.c
	scap_fds.c
	scap_iflist.c
	scap_savefile.c
	scap_procs.c
	scap_userlist.c)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}) # temporary
    include_directories(${PROJECT_BINARY_DIR}/driver/src)
endif()

if(CYGWIN OR WIN32)
	list(APPEND targetfiles
		windows_hal.c)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(scap STATIC
	${targetfiles})

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)
elseif (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
elseif (CYGWIN)
	target_link_libraries(scap
		/lib/w32api/libpsapi.a
		${WIN_HAL_LIB}/dragent_win_hal.lib)
endif()

if(NOT MINIMAL_BUILD)
target_link_libraries(scap
	"${ZLIB_LIB}")
endif()

add_library(scap_error strerror.c)

target_link_libraries(scap scap_error)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()

	include(FindMakedev)
endif()

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS AND NOT WIN32)
	# Add engine only used for testing
	add_definitions(-DHAS_ENGINE_TEST_INPUT)
	add_subdirectory(engine/test_input)
	target_link_libraries(scap scap_engine_test_input)

	# Add unit test directories
	add_subdirectory(test)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_subdirectory(linux)
	include_directories(linux)
elseif(WIN32)
	add_subdirectory(win32)
	include_directories(win32)
elseif(APPLE)
	add_subdirectory(macos)
	include_directories(macos)
endif()

target_link_libraries(scap scap_platform)

add_library(scap_event_schema
		scap_event.c
		syscall_info_table.c
		../../driver/dynamic_params_table.c
		../../driver/event_table.c
		../../driver/flags_table.c
		../../driver/tp_table.c)

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
	add_dependencies(scap_event_schema zlib)
endif()

target_link_libraries(scap scap_event_schema)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_library(driver_event_schema
		../../driver/syscall_table.c
		../../driver/fillers_table.c)
	target_link_libraries(scap_event_schema driver_event_schema)
endif()

add_library(scap_engine_util
	scap_engine_util.c
	ringbuffer/devset.c
	ringbuffer/ringbuffer.c)

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
	add_dependencies(scap_engine_util zlib)
endif()

target_link_libraries(scap scap_engine_util)

add_definitions(-DHAS_ENGINE_NOOP)
add_subdirectory(engine/noop)
# don't link the noop engine to libscap directly,
# it's a helper library for other engines (it's completely useless on its own)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-DHAS_ENGINE_NODRIVER)
	add_subdirectory(engine/nodriver)
	target_link_libraries(scap scap_engine_nodriver)
endif()

add_definitions(-DHAS_ENGINE_SAVEFILE)
add_subdirectory(engine/savefile)
target_link_libraries(scap scap_engine_savefile)

add_definitions(-DHAS_ENGINE_SOURCE_PLUGIN)
add_subdirectory(engine/source_plugin)
target_link_libraries(scap scap_engine_source_plugin)

if(NOT APPLE)
	add_definitions(-DHAS_ENGINE_UDIG)
	add_subdirectory(engine/udig)
	target_link_libraries(scap scap_engine_udig)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
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
		target_link_libraries(scap scap_engine_gvisor)
	endif()
endif()
