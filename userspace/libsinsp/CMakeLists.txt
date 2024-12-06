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

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)
option(ENABLE_THREAD_POOL "Enable inspector thread pool" OFF)

if(NOT MSVC)
	add_definitions(-DHAVE_PWD_H)
	add_definitions(-DHAVE_GRP_H)
	if(MUSL_OPTIMIZED_BUILD)
		add_definitions(-DMUSL_OPTIMIZED)
	endif()

	add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
	add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})
endif()

include(ExternalProject)

include(BuildPkgConfigDependencies)
include(jsoncpp)
include(zlib)
include(tbb)

add_library(
	sinsp
	filter/ast.cpp
	filter/escaping.cpp
	filter/parser.cpp
	filter/ppm_codes.cpp
	sinsp_cycledumper.cpp
	event.cpp
	eventformatter.cpp
	dns_manager.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	sinsp_filter_transformer.cpp
	sinsp_filtercheck.cpp
	sinsp_filtercheck_event.cpp
	sinsp_filtercheck_evtin.cpp
	sinsp_filtercheck_fd.cpp
	sinsp_filtercheck_fdlist.cpp
	sinsp_filtercheck_fspath.cpp
	sinsp_filtercheck_gen_event.cpp
	sinsp_filtercheck_group.cpp
	sinsp_filtercheck_mesos.cpp
	sinsp_filtercheck_rawstring.cpp
	sinsp_filtercheck_reference.cpp
	sinsp_filtercheck_syslog.cpp
	sinsp_filtercheck_thread.cpp
	sinsp_filtercheck_tracer.cpp
	sinsp_filtercheck_user.cpp
	sinsp_filtercheck_utils.cpp
	filter_compare.cpp
	filter_check_list.cpp
	ifinfo.cpp
	metrics_collector.cpp
	logger.cpp
	parsers.cpp
	${LIBS_DIR}/userspace/plugin/plugin_loader.c
	plugin.cpp
	plugin_table_api.cpp
	plugin_filtercheck.cpp
	prefix_search.cpp
	sinsp_syslog.cpp
	threadinfo.cpp
	tuples.cpp
	sinsp.cpp
	token_bucket.cpp
	utils.cpp
	value_parser.cpp
	user.cpp
	gvisor_config.cpp
	sinsp_suppress.cpp
	events/sinsp_events.cpp
	events/sinsp_events_ppm_sc.cpp
)

if(NOT WIN32
   AND NOT APPLE
   AND NOT EMSCRIPTEN
)
	target_sources(sinsp PRIVATE linux/resource_utilization.cpp)
endif()

if(ENABLE_THREAD_POOL AND NOT EMSCRIPTEN)
	target_sources(sinsp PRIVATE sinsp_thread_pool_bs.cpp)
endif()

if(NOT WIN32 AND NOT APPLE)
	target_sources(sinsp PRIVATE procfs_utils.cpp sinsp_cgroup.cpp)
endif()

target_include_directories(
	sinsp
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<BUILD_INTERFACE:${LIBS_DIR}/userspace>
		   $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/${LIBS_PACKAGE_NAME}>
)

if(EMSCRIPTEN)
	target_compile_options(sinsp PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
endif()

set_sinsp_target_properties(sinsp)

target_link_libraries(
	sinsp
	PUBLIC scap
	PRIVATE "${JSONCPP_LIB}" "${RE2_LIB}"
)

if(NOT EMSCRIPTEN)
	target_link_libraries(sinsp PRIVATE "${TBB_LIB}")
endif()

if(USE_BUNDLED_VALIJSON)
	add_dependencies(sinsp valijson)
endif()

if(USE_BUNDLED_RE2)
	add_dependencies(sinsp re2)
endif()

if(USE_BUNDLED_JSONCPP)
	add_dependencies(sinsp jsoncpp)
endif()

if(ENABLE_THREAD_POOL AND USE_BUNDLED_BS_THREADPOOL)
	add_dependencies(sinsp bs_threadpool)
endif()

if(NOT EMSCRIPTEN)
	add_dependencies(sinsp tbb)
endif()

if(NOT WIN32)
	if(NOT APPLE)
		if(NOT EMSCRIPTEN)
			if(NOT MUSL_OPTIMIZED_BUILD)
				find_library(LIB_ANL anl)
				if(LIB_ANL)
					target_link_libraries(sinsp INTERFACE rt anl)
				else()
					target_link_libraries(sinsp INTERFACE rt)
				endif()
			endif()

		else()
			target_link_libraries(sinsp INTERFACE rt)
		endif() # NOT EMSCRIPTEN
	endif() # NOT APPLE

	target_link_libraries(sinsp INTERFACE dl pthread)

	if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
			target_link_libraries(sinsp INTERFACE stdc++fs)
		endif()
	endif()
endif() # NOT WIN32

if(APPLE)
	target_link_libraries(sinsp PRIVATE "-framework CoreFoundation")
	target_link_libraries(sinsp PRIVATE "-framework SystemConfiguration")
	set_target_properties(sinsp PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks")
endif()

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS)
	# Add unit test directories
	add_subdirectory(test)
endif()

option(BUILD_LIBSINSP_EXAMPLES "Build libsinsp examples" ON)
if(BUILD_LIBSINSP_EXAMPLES)
	add_subdirectory(examples)
	add_subdirectory(sinsp_debug)
endif()

if(NOT DEFINED SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR)
	set(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR "AGENT_CGROUP_MEM_PATH")
endif()
add_definitions(-DSINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR="${SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR}")

# Build our pkg-config "Libs:" flags. For now, loop over SINSP_PKGCONFIG_LIBRARIES. If we ever start
# using pkg_search_module or pkg_check_modules in cmake/modules we could add each module to our
# "Requires:" line instead. We might need to expand this to use some of the techniques in
# https://github.com/curl/curl/blob/curl-7_84_0/CMakeLists.txt#L1539
set(SINSP_PKG_CONFIG_LIBS)
set(SINSP_PKG_CONFIG_LIBDIRS "")
add_pkgconfig_dependency(SINSP_PKG_CONFIG_LIBDIRS SINSP_PKG_CONFIG_LIBS sinsp scap)

# Build our pkg-config "Cflags:" flags.
set(SINSP_PKG_CONFIG_INCLUDES "")
foreach(sinsp_include_directory ${LIBSINSP_INCLUDE_DIRS})
	list(APPEND SINSP_PKG_CONFIG_INCLUDES -I${sinsp_include_directory})
endforeach()

string(REPLACE ";" " " SINSP_PKG_CONFIG_LIBS "${SINSP_PKG_CONFIG_LIBS}")
list(REMOVE_DUPLICATES SINSP_PKG_CONFIG_LIBDIRS)
string(REPLACE ";" " " SINSP_PKG_CONFIG_LIBDIRS "${SINSP_PKG_CONFIG_LIBDIRS}")
list(REMOVE_DUPLICATES SINSP_PKG_CONFIG_INCLUDES)
string(REPLACE ";" " " SINSP_PKG_CONFIG_INCLUDES "${SINSP_PKG_CONFIG_INCLUDES}")
configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/libsinsp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libsinsp.pc @ONLY
)
