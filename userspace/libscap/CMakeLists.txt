# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

include(engine_config)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

include(zlib)

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})

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


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scap_strl_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/scap_strl_config.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scap_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/scap_config.h)


add_library(scap_error STATIC strerror.c)

target_include_directories(scap_error PUBLIC $<BUILD_INTERFACE:${LIBS_DIR}/userspace>)

add_library(scap
	scap.c
	scap_api_version.c
	scap_savefile.c
	scap_platform_api.c
)

target_include_directories(scap
PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/${LIBS_PACKAGE_NAME}>
)

set_scap_target_properties(scap)

add_library(scap_platform_util STATIC
	scap_platform.c
	scap_fds.c
	scap_iflist.c
	scap_proc_util.c
	scap_procs.c
	scap_userlist.c
)
add_dependencies(scap_platform_util uthash)

target_include_directories(scap_platform_util
PUBLIC
	$<BUILD_INTERFACE:${LIBS_DIR}>
	$<BUILD_INTERFACE:${LIBS_DIR}/userspace>
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
)

target_link_libraries(scap
PRIVATE
	scap_error
	"${ZLIB_LIB}"
)

add_library(scap_event_schema STATIC
	scap_event.c
	ppm_sc_names.c
	${LIBS_DIR}/driver/dynamic_params_table.c
	${LIBS_DIR}/driver/event_table.c
	${LIBS_DIR}/driver/flags_table.c
	${LIBS_DIR}/driver/syscall_table64.c
	${LIBS_DIR}/driver/syscall_ia32_64_map.c
	linux/scap_ppm_sc.c
)

add_dependencies(scap_event_schema uthash)

target_include_directories(scap_event_schema
PUBLIC
	$<BUILD_INTERFACE:${LIBS_DIR}>
	$<BUILD_INTERFACE:${LIBS_DIR}/userspace>
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
)

target_link_libraries(scap PUBLIC scap_event_schema)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)
	include(FindMakedev)

	add_subdirectory(linux)
	target_link_libraries(scap PUBLIC scap_platform)


	add_library(driver_event_schema STATIC
		${LIBS_DIR}/driver/fillers_table.c)

	target_link_libraries(scap_event_schema driver_event_schema)


	add_library(scap_engine_util STATIC
		scap_engine_util.c
		ringbuffer/devset.c
		ringbuffer/ringbuffer.c
	)
	add_dependencies(scap_engine_util uthash)
	target_include_directories(scap_engine_util
	PUBLIC
		$<BUILD_INTERFACE:${LIBS_DIR}>
		$<BUILD_INTERFACE:${LIBS_DIR}/userspace>
		$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
	)
	target_link_libraries(scap PRIVATE scap_engine_util)
endif()


################## LISCAP ENGINES ##################

add_subdirectory(engine/noop)
# don't link the noop engine to libscap directly,
# it's a helper library for other engines (it's completely useless on its own)

if(HAS_ENGINE_NODRIVER)
	add_subdirectory(engine/nodriver)
	target_link_libraries(scap PUBLIC scap_engine_nodriver)
endif()

if(HAS_ENGINE_TEST_INPUT)
	# Add engine only used for testing
	add_subdirectory(engine/test_input)
	target_link_libraries(scap PUBLIC scap_engine_test_input)
endif()

if(HAS_ENGINE_SAVEFILE)
	add_subdirectory(engine/savefile)
	target_link_libraries(scap PUBLIC scap_engine_savefile)
endif()

if(HAS_ENGINE_SOURCE_PLUGIN)
	add_subdirectory(engine/source_plugin)
	target_link_libraries(scap PUBLIC scap_engine_source_plugin)
endif()

if(HAS_ENGINE_KMOD)
	add_subdirectory(engine/kmod)
	target_link_libraries(scap PUBLIC scap_engine_kmod)
	target_include_directories(scap_engine_kmod
	PRIVATE
		${PROJECT_BINARY_DIR}/driver/src
	)
endif()

if(HAS_ENGINE_BPF)
	include(libelf)
	add_subdirectory(engine/bpf)
	target_link_libraries(scap PUBLIC scap_engine_bpf)
	target_include_directories(scap_engine_bpf
	PRIVATE
		${PROJECT_BINARY_DIR}/driver/src
	)
endif()

if(HAS_ENGINE_MODERN_BPF)
	include(libelf)
	add_subdirectory(engine/modern_bpf)
	target_link_libraries(scap PUBLIC scap_engine_modern_bpf)
	target_include_directories(scap_engine_modern_bpf
	PRIVATE
		${PROJECT_BINARY_DIR}/driver/src
	)
endif()

if(HAS_ENGINE_GVISOR)
	add_subdirectory(engine/gvisor)
	# The static and shared build differs here because a shared scap_engine_gvisor
	# will result in circular dependencies.
	if(BUILD_SHARED_LIBS)
		# We can move this to the gvisor CMakeFile when we use
		# CMake 3.13 or later.
		# https://cmake.org/cmake/help/latest/policy/CMP0079.html
		target_link_libraries(scap
		PRIVATE
			${CMAKE_THREAD_LIBS_INIT}
			${PROTOBUF_LIB}
			${JSONCPP_LIB}
		)
	else()
		target_link_libraries(scap PRIVATE scap_engine_gvisor)
	endif()
endif()

####################################################

if (BUILD_LIBSCAP_EXAMPLES)
	add_subdirectory(examples/01-open)
	add_subdirectory(examples/02-validatebuffer)
endif()
