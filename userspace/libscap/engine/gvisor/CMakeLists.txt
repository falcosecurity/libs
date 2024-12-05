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
include(protobuf)
include(jsoncpp)

find_package(Threads)

set(scap_engine_gvisor_sources
	${CMAKE_CURRENT_SOURCE_DIR}/parsers.cpp ${CMAKE_CURRENT_SOURCE_DIR}/fillers.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/gvisor.cpp ${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/scap_gvisor_platform.cpp ${CMAKE_CURRENT_SOURCE_DIR}/runsc.cpp
)

set(scap_engine_gvisor_generated_sources
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.cc
)

set(scap_engine_gvisor_generated_headers
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/common.pb.h
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/container.pb.h
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/sentry.pb.h
	${CMAKE_CURRENT_BINARY_DIR}/pkg/sentry/seccheck/points/syscall.pb.h
)

add_custom_command(
	OUTPUT ${scap_engine_gvisor_generated_sources} ${scap_engine_gvisor_generated_headers}
	COMMENT "Generate gVisor protobuf definitions"
	DEPENDS protobuf
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
	COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=.
			${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/common.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
	COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=.
			${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/container.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
	COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=.
			${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/sentry.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
	COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out=.
			${CMAKE_CURRENT_SOURCE_DIR}/proto/pkg/sentry/seccheck/points/syscall.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_library(
	scap_engine_gvisor ${scap_engine_gvisor_sources} ${scap_engine_gvisor_generated_sources}
)

add_dependencies(scap_engine_gvisor uthash jsoncpp scap_event_schema)
target_link_libraries(
	scap_engine_gvisor PUBLIC scap_platform_util scap_error ${CMAKE_THREAD_LIBS_INIT}
							  ${PROTOBUF_LIB} ${JSONCPP_LIB} scap_event_schema
)

target_include_directories(scap_engine_gvisor PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

set_scap_target_properties(scap_engine_gvisor)
