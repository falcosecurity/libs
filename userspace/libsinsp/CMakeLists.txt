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

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

if(NOT MSVC)
	add_definitions(-DHAVE_PWD_H)
	add_definitions(-DHAVE_GRP_H)
	if(MUSL_OPTIMIZED_BUILD)
		add_definitions(-DMUSL_OPTIMIZED)
	endif()
endif()

if(NOT DEFINED CHISEL_TOOL_LIBRARY_NAME)
	set(CHISEL_TOOL_LIBRARY_NAME "sinsp")
endif()
add_definitions(-DCHISEL_TOOL_LIBRARY_NAME="${CHISEL_TOOL_LIBRARY_NAME}")

include(ExternalProject)

include(jsoncpp)
if(WITH_CHISEL)
	include(luajit)
endif()

include(zlib)

if(NOT MINIMAL_BUILD)
	if (NOT WIN32 AND NOT EMSCRIPTEN)
		include(curl)
		include(cares)
	endif() # NOT WIN32
endif()

if(NOT WIN32 AND NOT APPLE )
	if(NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
		include(grpc)
		include(protobuf)
		include(openssl)
	endif() # NOT MINIMAL_BUILD
endif()

if (NOT EMSCRIPTEN)
	include(tbb)
endif()

add_library(sinsp
	filter/ast.cpp
	filter/escaping.cpp
	filter/parser.cpp
	filter/ppm_codes.cpp
	container.cpp
	container_engine/container_engine_base.cpp
	container_engine/static_container.cpp
	container_info.cpp
	sinsp_cycledumper.cpp
	event.cpp
	eventformatter.cpp
	dns_manager.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	sinsp_filtercheck.cpp
	sinsp_filtercheck_container.cpp
	sinsp_filtercheck_event.cpp
	sinsp_filtercheck_evtin.cpp
	sinsp_filtercheck_fd.cpp
	sinsp_filtercheck_fdlist.cpp
	sinsp_filtercheck_fspath.cpp
	sinsp_filtercheck_gen_event.cpp
	sinsp_filtercheck_group.cpp
	sinsp_filtercheck_k8s.cpp
	sinsp_filtercheck_mesos.cpp
	sinsp_filtercheck_rawstring.cpp
	sinsp_filtercheck_reference.cpp
	sinsp_filtercheck_syslog.cpp
	sinsp_filtercheck_thread.cpp
	sinsp_filtercheck_tracer.cpp
	sinsp_filtercheck_user.cpp
	sinsp_filtercheck_utils.cpp
	filter_check_list.cpp
	ifinfo.cpp
	memmem.cpp
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
	stats.cpp
	token_bucket.cpp
	utils.cpp
	value_parser.cpp
	user.cpp
	gvisor_config.cpp
	sinsp_suppress.cpp
	events/sinsp_events.cpp
	events/sinsp_events_ppm_sc.cpp
)

if(NOT WIN32 AND NOT APPLE)
	target_sources(sinsp PRIVATE procfs_utils.cpp sinsp_cgroup.cpp)
endif()

if(WITH_CHISEL)
	target_sources(sinsp
	PRIVATE
		${LIBS_DIR}/userspace/chisel/chisel_api.cpp
		${LIBS_DIR}/userspace/chisel/chisel_fields_info.cpp
		${LIBS_DIR}/userspace/chisel/chisel_utils.cpp
		${LIBS_DIR}/userspace/chisel/chisel.cpp
		${LIBS_DIR}/userspace/chisel/chisel_viewinfo.cpp
		${LIBS_DIR}/userspace/chisel/chisel_table.cpp
	)
endif()

if(NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
	target_sources(sinsp
	PRIVATE
		container_engine/docker/async_source.cpp
		container_engine/docker/base.cpp
	)
	if(NOT WIN32)
		target_sources(sinsp
		PRIVATE
			container_engine/docker/docker_linux.cpp
			container_engine/docker/connection_linux.cpp
			container_engine/docker/podman.cpp
			container_engine/libvirt_lxc.cpp
			container_engine/lxc.cpp
			container_engine/mesos.cpp
			container_engine/rkt.cpp
			container_engine/bpm.cpp
			cri_settings.cpp
			runc.cpp
		)
	endif()

	if(NOT WIN32 AND NOT APPLE)
		target_sources(sinsp
		PRIVATE
			cgroup_limits.cpp
			container_engine/cri.cpp
			grpc_channel_registry.cpp
		)
	endif()
endif()

target_include_directories(sinsp
PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<BUILD_INTERFACE:${LIBS_DIR}/userspace>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/${LIBS_PACKAGE_NAME}>
)

if (EMSCRIPTEN)
	target_compile_options(sinsp PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
endif()

set_sinsp_target_properties(sinsp)

target_link_libraries(sinsp
		PUBLIC scap
		PRIVATE
			"${CURL_LIBRARIES}"
			"${JSONCPP_LIB}"
			"${RE2_LIB}"
)

set(SINSP_PKGCONFIG_LIBRARIES
	scap
	"${ZLIB_LIB}"
	"${CURL_LIBRARIES}"
	"${JSONCPP_LIB}"
	"${RE2_LIB}"
)

if(NOT EMSCRIPTEN)
	target_link_libraries(sinsp
		INTERFACE
			"${CARES_LIB}"
		PRIVATE
		"${TBB_LIB}"
	)
	list(APPEND SINSP_PKGCONFIG_LIBRARIES "${CARES_LIB}")
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

if(WITH_CHISEL)
	add_dependencies(sinsp luajit)
endif()

function(prepare_cri_grpc api_version)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cri-${api_version}.proto ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.proto COPYONLY)
	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.grpc.pb.cc
			${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.grpc.pb.h
			${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.pb.cc
			${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.pb.h
			COMMENT "Generate CRI grpc code for API version ${api_version}"
			DEPENDS
			COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.proto
			COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.proto
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
	add_library(cri_${api_version} STATIC ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/cri-${api_version}.grpc.pb.cc)
	target_include_directories(cri_${api_version}
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
	)
	add_dependencies(cri_${api_version} grpc)
endfunction()

if (NOT EMSCRIPTEN)
	add_dependencies(sinsp tbb)
endif()

if(NOT WIN32)
	if(NOT MINIMAL_BUILD)
		if(NOT EMSCRIPTEN)
			add_dependencies(sinsp openssl curl)
		endif()
	endif()

	if(NOT APPLE)
		if(NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
			include(protobuf)
			include(cares)
			prepare_cri_grpc(v1alpha2)
			prepare_cri_grpc(v1)

			target_link_libraries(sinsp
					PRIVATE
						cri_v1alpha2
						cri_v1
					INTERFACE
						"${GRPC_LIBRARIES}"
						"${GRPCPP_LIB}"
						"${GRPC_LIB}"
						"${GPR_LIB}"
						"${PROTOBUF_LIB}"
						"${CARES_LIB}"
			)
			list(APPEND SINSP_PKGCONFIG_LIBRARIES
						"${GRPC_LIBRARIES}"
						"${GRPCPP_LIB}"
						"${GRPC_LIB}"
						"${GPR_LIB}"
						"${PROTOBUF_LIB}"
						"${CARES_LIB}"
			)

			if(NOT MUSL_OPTIMIZED_BUILD)
				target_link_libraries(sinsp INTERFACE rt anl)
				list(APPEND SINSP_PKGCONFIG_LIBRARIES rt anl)
			endif()

		else()
			target_link_libraries(sinsp INTERFACE rt)
			list(APPEND SINSP_PKGCONFIG_LIBRARIES rt)
		endif() # NOT MINIMAL_BUILD
	endif() # NOT APPLE

	target_link_libraries(sinsp INTERFACE "${OPENSSL_LIBRARIES}")
	list(APPEND SINSP_PKGCONFIG_LIBRARIES "${OPENSSL_LIBRARIES}")

	if(WITH_CHISEL)
		target_link_libraries(sinsp INTERFACE "${LUAJIT_LIB}")
		list(APPEND SINSP_PKGCONFIG_LIBRARIES "${LUAJIT_LIB}")
	endif()

	target_link_libraries(sinsp INTERFACE dl pthread)
	list(APPEND SINSP_PKGCONFIG_LIBRARIES dl pthread)

	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
			target_link_libraries(sinsp INTERFACE stdc++fs)
			list(APPEND SINSP_PKGCONFIG_LIBRARIES stdc++fs)
		endif()
	endif()
else()
	if(WITH_CHISEL)
		target_link_libraries(sinsp INTERFACE "${LUAJIT_LIB}")
		list(APPEND SINSP_PKGCONFIG_LIBRARIES "${LUAJIT_LIB}")
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
if (BUILD_LIBSINSP_EXAMPLES)
	add_subdirectory(examples)
	add_subdirectory(sinsp_debug)
endif()

if(NOT DEFINED SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR)
	set(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR "AGENT_CGROUP_MEM_PATH")
endif()
add_definitions(-DSINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR="${SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR}")

# Build our pkg-config "Libs:" flags. For now, loop over SINSP_PKGCONFIG_LIBRARIES. If
# we ever start using pkg_search_module or pkg_check_modules in cmake/modules
# we could add each module to our "Requires:" line instead. We might need to
# expand this to use some of the techniques in
# https://github.com/curl/curl/blob/curl-7_84_0/CMakeLists.txt#L1539
set(SINSP_PKG_CONFIG_LIBS)
set(SINSP_PKG_CONFIG_LIBDIRS "")
foreach(sinsp_lib ${SINSP_PKGCONFIG_LIBRARIES})
	if(${sinsp_lib} MATCHES "^-")
		# We have a flag. Pass it through unchanged.
		list(APPEND SINSP_PKG_CONFIG_LIBS ${sinsp_lib})
	elseif(${sinsp_lib} MATCHES "/")
		# We have a path. Convert it to -L<dir> + -l<lib>.
		get_filename_component(sinsp_lib_dir ${sinsp_lib} DIRECTORY)
		list(APPEND SINSP_PKG_CONFIG_LIBDIRS -L${sinsp_lib_dir})
		get_filename_component(sinsp_lib_base ${sinsp_lib} NAME_WE)
		string(REGEX REPLACE "^lib" "" sinsp_lib_base ${sinsp_lib_base})
		list(APPEND SINSP_PKG_CONFIG_LIBS -l${sinsp_lib_base})
	elseif(${sinsp_lib} STREQUAL "scap")
		# We require libscap.pc, so skip it.
	else()
		# Assume we have a plain library name. Prefix it with "-l".
		list(APPEND SINSP_PKG_CONFIG_LIBS -l${sinsp_lib})
	endif()
endforeach()

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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libsinsp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libsinsp.pc @ONLY)
