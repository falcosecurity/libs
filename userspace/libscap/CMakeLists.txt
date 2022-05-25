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
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../../common")

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

if(WIN32 OR NOT MINIMAL_BUILD)
	include(zlib)
endif()

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	endif()

    if(NOT DEFINED DRIVER_VERSION)
        set(DRIVER_VERSION "${FALCOSECURITY_LIBS_VERSION}")
    endif()

    if(NOT DEFINED DRIVER_NAME)
        set(DRIVER_NAME "scap")
    endif()
	
    if(NOT DEFINED DRIVER_DEVICE_NAME)
        set(DRIVER_DEVICE_NAME "${DRIVER_NAME}")
    endif()

	string(REPLACE "-" "_" SCAP_KERNEL_MODULE_NAME "${DRIVER_NAME}")
	add_definitions(-DSCAP_KERNEL_MODULE_NAME="${SCAP_KERNEL_MODULE_NAME}")

	if(NOT DEFINED SCAP_PROBE_BPF_FILEPATH)
		# note that the home folder is prepended by scap at runtime
		set(SCAP_PROBE_BPF_FILEPATH ".${DRIVER_NAME}/${DRIVER_NAME}-bpf.o")
	endif()
	add_definitions(-DSCAP_PROBE_BPF_FILEPATH="${SCAP_PROBE_BPF_FILEPATH}")
endif()

if(NOT DEFINED SCAP_BPF_PROBE_ENV_VAR_NAME)
	set(SCAP_BPF_PROBE_ENV_VAR_NAME "BPF_PROBE") 
endif()
add_definitions(-DSCAP_BPF_PROBE_ENV_VAR_NAME="${SCAP_BPF_PROBE_ENV_VAR_NAME}")

if(NOT DEFINED SCAP_HOST_ROOT_ENV_VAR_NAME)
	set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")
endif()
add_definitions(-DSCAP_HOST_ROOT_ENV_VAR_NAME="${SCAP_HOST_ROOT_ENV_VAR_NAME}")

if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

list(APPEND targetfiles
	scap.c
	scap_event.c
	scap_fds.c
	scap_iflist.c
	scap_savefile.c
	scap_procs.c
	scap_userlist.c
	../../driver/dynamic_params_table.c
	../../driver/event_table.c
	../../driver/flags_table.c)

if(NOT APPLE)
	list(APPEND targetfiles
		scap_udig.c)
endif()


if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND targetfiles
		scap_bpf.c
		../../driver/syscall_table.c
		../../driver/fillers_table.c)

    include_directories(${PROJECT_BINARY_DIR}/driver/src)
endif()

if(CYGWIN OR WIN32)
	list(APPEND targetfiles
		windows_hal.c)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(scap STATIC
	${targetfiles})

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
	add_dependencies(scap zlib)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_link_libraries(scap
		elf
		rt)
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

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_subdirectory(../../driver ${PROJECT_BINARY_DIR}/driver)

    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()

	include(FindMakedev)
endif()


# gVisor is currently only supported on Linux
if(NOT MINIMAL_BUILD AND NOT WIN32 AND NOT APPLE)
	option(BUILD_LIBSCAP_GVISOR "Build gVisor support" ON)
	if (BUILD_LIBSCAP_GVISOR)
		add_definitions(-DHAS_ENGINE_GVISOR)
		add_subdirectory(engine/gvisor)
		target_link_libraries(scap scap_engine_gvisor)
	endif()
endif()

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add unit test directories
		add_subdirectory(test)
endif()
