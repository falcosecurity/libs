#
# Copyright (C) 2021 The Falco Authors.
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
include_directories(./)
include_directories(../../common)
include_directories(${LIBSCAP_INCLUDE_DIR})
include_directories(../async)
include_directories(./include)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

if(NOT WIN32 AND NOT APPLE)
	include(b64)
endif()

include(jsoncpp)
if(WITH_CHISEL)
	include_directories(../chisel)
	include(luajit)
endif()

if(NOT MINIMAL_BUILD)
	include(cares)
endif()

if(NOT WIN32 AND NOT APPLE)
	if(NOT MINIMAL_BUILD)
		include(grpc)
		include(protobuf)
		include(openssl)
		include(curl)
	endif() # NOT MINIMAL_BUILD
	include(jq)
	include_directories("${CMAKE_CURRENT_BINARY_DIR}")
endif()

if(NOT WIN32)
	include(tbb)
endif()

set(SINSP_SOURCES
	container.cpp
	container_engine/container_engine_base.cpp
	container_engine/static_container.cpp
	container_info.cpp
	cyclewriter.cpp
	event.cpp
	eventformatter.cpp
	dns_manager.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	fields_info.cpp
	filterchecks.cpp
	gen_filter.cpp
	http_parser.c
	http_reason.cpp
	ifinfo.cpp
	json_query.cpp
	json_error_log.cpp
	memmem.cpp
	tracers.cpp
	internal_metrics.cpp
	"${JSONCPP_LIB_SRC}"
	logger.cpp
	parsers.cpp
	prefix_search.cpp
	protodecoder.cpp
	threadinfo.cpp
	tuples.cpp
	sinsp.cpp
	stats.cpp
	table.cpp
	token_bucket.cpp
	stopwatch.cpp
	uri_parser.c
	uri.cpp
	user_event_logger.cpp
	utils.cpp
	user_event.cpp
	value_parser.cpp
	viewinfo.cpp
)

if(WITH_CHISEL)
	list(APPEND SINSP_SOURCES
		../chisel/chisel_api.cpp
		../chisel/chisel_fields_info.cpp
		../chisel/chisel_utils.cpp
		../chisel/chisel.cpp
		../chisel/lua_parser_api.cpp
		../chisel/lua_parser.cpp)
endif()

if(NOT MINIMAL_BUILD)
	list(APPEND SINSP_SOURCES
		addrinfo.cpp
		sinsp_auth.cpp
		k8s.cpp
		k8s_api_error.cpp
		k8s_api_handler.cpp
		k8s_component.cpp
		k8s_daemonset_handler.cpp
		k8s_deployment_handler.cpp
		k8s_dispatcher.cpp
		k8s_event_data.cpp
		k8s_event_handler.cpp
		k8s_handler.cpp
		k8s_namespace_handler.cpp
		k8s_net.cpp
		k8s_node_handler.cpp
		k8s_pod_handler.cpp
		k8s_replicationcontroller_handler.cpp
		k8s_replicaset_handler.cpp
		k8s_service_handler.cpp
		k8s_state.cpp
		marathon_component.cpp
		marathon_http.cpp
		mesos_auth.cpp
		mesos.cpp
		mesos_collector.cpp
		mesos_component.cpp
		mesos_http.cpp
		mesos_state.cpp
		sinsp_curl.cpp
		container_engine/docker_common.cpp)
	if(WIN32)
	list(APPEND SINSP_SOURCES
		container_engine/docker_win.cpp)
	else()
	list(APPEND SINSP_SOURCES
		container_engine/docker_linux.cpp
		container_engine/libvirt_lxc.cpp
		container_engine/lxc.cpp
		container_engine/mesos.cpp
		container_engine/rkt.cpp
		container_engine/bpm.cpp
		runc.cpp)
	endif()

	if(NOT WIN32 AND NOT APPLE)
		list(APPEND SINSP_SOURCES
			cgroup_limits.cpp
			cri.cpp
			container_engine/cri.cpp
			${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
			${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
			grpc_channel_registry.cpp
		)
	endif()
endif()

add_library(sinsp STATIC ${SINSP_SOURCES})

set(SINSP_LIBRARIES
	scap
	"${CURL_LIBRARIES}"
	"${JSONCPP_LIB}"
	"${CARES_LIB}")

if(WITH_CHISEL AND USE_BUNDLED_LUAJIT)
	add_dependencies(sinsp luajit)
endif()

if(NOT WIN32)
	list(APPEND SINSP_LIBRARIES "${TBB_LIB}")

	if(USE_BUNDLED_OPENSSL AND NOT MINIMAL_BUILD)
		add_dependencies(sinsp openssl)
	endif() # USE_BUNDLED_OPENSSL
	if(USE_BUNDLED_CURL AND NOT MINIMAL_BUILD)
		add_dependencies(sinsp curl)
	endif() # USE_BUNDLED_CURL
	if(USE_BUNDLED_TBB)
		add_dependencies(sinsp tbb)
	endif() # USE_BUNDLED_TBB


	if(NOT APPLE)
		if(NOT MINIMAL_BUILD)
			include(protobuf)
			include(cares)
			configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cri.proto ${CMAKE_CURRENT_BINARY_DIR}/cri.proto COPYONLY)
			add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
						${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.h
						${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
						${CMAKE_CURRENT_BINARY_DIR}/cri.pb.h
					COMMENT "Generate CRI grpc code"
					DEPENDS
					COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/cri.proto
					COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${CMAKE_CURRENT_BINARY_DIR}/cri.proto
					WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

			if(USE_BUNDLED_GRPC)
				add_dependencies(sinsp grpc)
				list(APPEND SINSP_LIBRARIES "${GRPC_LIBRARIES}")
			endif() # USE_BUNDLED_GRPC

			list(APPEND SINSP_LIBRARIES
				"${GRPCPP_LIB}"
				"${GRPC_LIB}"
				"${GPR_LIB}"
				"${PROTOBUF_LIB}"
				"${CARES_LIB}"
				"${JQ_LIB}"
				"${B64_LIB}")

			if(NOT MUSL_OPTIMIZED_BUILD)
				list(APPEND SINSP_LIBRARIES
				rt
				anl)
			endif()

		else()
			list(APPEND SINSP_LIBRARIES
				"${JQ_LIB}"
				"${B64_LIB}"
				rt)
		endif() # NOT MINIMAL_BUILD
		# when JQ is compiled statically, it will
		# also compile a static object for oniguruma we need to link
		if(ONIGURUMA_LIB)
			list(APPEND SINSP_LIBRARIES
			"${ONIGURUMA_LIB}")
			add_dependencies(sinsp jq)
		endif()

		if(USE_BUNDLED_B64)
			add_dependencies(sinsp b64)
		endif()
	endif() # NOT APPLE

        if(USE_BUNDLED_OPENSSL AND NOT MINIMAL_BUILD)
		list(APPEND SINSP_LIBRARIES
			"${OPENSSL_LIBRARY_SSL}"
			"${OPENSSL_LIBRARY_CRYPTO}")
        else()
		list(APPEND SINSP_LIBRARIES
                    "${OPENSSL_LIBRARIES}")
        endif()

		if(WITH_CHISEL)
		list(APPEND SINSP_LIBRARIES
			"${LUAJIT_LIB}")
		endif()

		list(APPEND SINSP_LIBRARIES
			dl
			pthread)
else()
	if(WITH_CHISEL)
		list(APPEND SINSP_LIBRARIES
			"${LUAJIT_LIB}")
	endif()
endif() # NOT WIN32


target_link_libraries(sinsp ${SINSP_LIBRARIES})

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add unit test directories
		add_subdirectory(test)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(BUILD_LIBSINSP_EXAMPLES "Build libsinsp examples" ON)

    if (BUILD_LIBSINSP_EXAMPLES)
        add_subdirectory(examples)
    endif()
endif()

