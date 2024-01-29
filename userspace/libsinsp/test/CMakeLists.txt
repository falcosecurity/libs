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

include(jsoncpp)
if (NOT EMSCRIPTEN)
	include(tbb)
endif()
if(NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
	include(curl)
endif() # MINIMAL_BUILD

include(zlib)

if(WIN32)
	set(CMAKE_CXX_FLAGS "-D_CRT_SECURE_NO_WARNINGS -DWIN32 -DMINIMAL_BUILD /EHsc /W3 /Zi /std:c++17")
	set(CMAKE_CXX_FLAGS_DEBUG "/MTd /Od")
	set(CMAKE_CXX_STANDARD 17)
endif()

# Create a libsinsp_test_var.h file with some variables used by our tests
configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/libsinsp_test_var.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libsinsp_test_var.h"
)

file(GLOB_RECURSE TEST_PLUGINS ${CMAKE_CURRENT_SOURCE_DIR}/plugins/*.cpp)

add_definitions(-DRESOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources")

if(NOT WIN32)
	file(GLOB_RECURSE SINSP_PARSERS_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/parsers/*.cpp)

	file(GLOB_RECURSE SINSP_CLASSES_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/classes/*.cpp)

	file(GLOB_RECURSE SINSP_FILTERCHECKS_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/filterchecks/*.cpp)

	file(GLOB_RECURSE SINSP_CONTAINER_ENGINE_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/container_engine/*.cpp)
endif()

option(SCAP_FILES_SUITE_ENABLE "Enable scap-file tests in sinsp" "ON")
# Scap-files on Big Endian systems are not supported
if((NOT ${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "s390x") AND ${SCAP_FILES_SUITE_ENABLE})
	# Binary dir in which we will save all our Cmake files
	file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/scap_files")
	# Add here the name for new scap-files
	set(SCAP_FILE_NAMES
	    "kexec_arm64.scap"
		"kexec_x86.scap"
	)
	set(SCAP_FILE_DOWNLOAD_PREFIX
		"https://download.falco.org/fixtures/libs/scap_files"
	)
	message(STATUS "Download all scap-files from: ${SCAP_FILE_DOWNLOAD_PREFIX}")
	foreach(FILE_NAME ${SCAP_FILE_NAMES})
		message(STATUS "Downloading scap-file: ${SCAP_FILE_DOWNLOAD_PREFIX}/${FILE_NAME}")
		if(NOT EXISTS "${CMAKE_BINARY_DIR}/scap_files/${FILE_NAME}")
			file(DOWNLOAD
			"${SCAP_FILE_DOWNLOAD_PREFIX}/${FILE_NAME}"
			"${CMAKE_BINARY_DIR}/scap_files/${FILE_NAME}"
			SHOW_PROGRESS)
		else()
			message(STATUS "Skipping download, file already present")
		endif()
	endforeach()
	file(GLOB_RECURSE SCAP_FILES_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/scap_files/*.cpp)
endif()

file(GLOB_RECURSE TEST_HELPERS ${CMAKE_CURRENT_SOURCE_DIR}/helpers/*.cpp)

set(LIBSINSP_UNIT_TESTS_SOURCES
	test_utils.cpp
	cgroup_list_counter.ut.cpp
	events_evt.ut.cpp
	events_file.ut.cpp
	events_fspath.ut.cpp
	events_injection.ut.cpp
	events_net.ut.cpp
	events_param.ut.cpp
	events_plugin.ut.cpp
	events_proc.ut.cpp
	events_user.ut.cpp
	external_processor.ut.cpp
	mpsc_priority_queue.ut.cpp
	token_bucket.ut.cpp
	ppm_api_version.ut.cpp
	plugins.ut.cpp
	plugin_manager.ut.cpp
	prefix_search.ut.cpp
	string_visitor.ut.cpp
	filtercheck_has_args.ut.cpp
	filter_escaping.ut.cpp
	filter_parser.ut.cpp
	filter_op_bcontains.ut.cpp
	filter_op_pmatch.ut.cpp
	filter_compiler.ut.cpp
	user.ut.cpp
	sinsp_utils.ut.cpp
	state.ut.cpp
	dns_manager.ut.cpp
	eventformatter.ut.cpp
	savefile.ut.cpp
	sinsp_stats.ut.cpp
	thread_table.ut.cpp
	ifinfo.ut.cpp
	public_sinsp_API/event_related.cpp
	public_sinsp_API/sinsp_logger.cpp
	"${TEST_PLUGINS}"
	"${SINSP_PARSERS_SUITE}"
	"${SINSP_CLASSES_SUITE}"
	"${SINSP_FILTERCHECKS_SUITE}"
	"${SCAP_FILES_SUITE}"
	"${TEST_HELPERS}"
	"${SINSP_CONTAINER_ENGINE_SUITE}"
)

if(WIN32)
	list(REMOVE_ITEM LIBSINSP_UNIT_TESTS_SOURCES
		events_file.ut.cpp
		events_fspath.ut.cpp
		events_net.ut.cpp
		events_proc.ut.cpp
		events_user.ut.cpp
		user.ut.cpp
		thread_table.ut.cpp
		public_sinsp_API/sinsp_logger.cpp
	)
elseif(APPLE OR EMSCRIPTEN)
	list(REMOVE_ITEM LIBSINSP_UNIT_TESTS_SOURCES
		events_net.ut.cpp
	)
endif()

add_definitions(-DVISIBILITY_PRIVATE=)

if(NOT MINIMAL_BUILD)
	list(APPEND LIBSINSP_UNIT_TESTS_SOURCES procfs_utils.ut.cpp)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND LIBSINSP_UNIT_TESTS_SOURCES
		async_key_value_source.ut.cpp
		filter_ppm_codes.ut.cpp
		public_sinsp_API/events_set.cpp
		public_sinsp_API/interesting_syscalls.cpp
		public_sinsp_API/ppm_sc_codes.cpp)
endif()

# Link against additional files could be useful when testing plugins
# `ADDITIONAL_SINSP_TESTS_SUITE` is a list of source files `;` separated
if(ADDITIONAL_SINSP_TESTS_SUITE)
	message(STATUS "- Additional sinsp source files: ${ADDITIONAL_SINSP_TESTS_SUITE}")
	list(APPEND LIBSINSP_UNIT_TESTS_SOURCES "${ADDITIONAL_SINSP_TESTS_SUITE}")
endif()

add_executable(unit-test-libsinsp ${LIBSINSP_UNIT_TESTS_SOURCES})

if (EMSCRIPTEN)
	target_compile_options(unit-test-libsinsp PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(unit-test-libsinsp PRIVATE "-sDISABLE_EXCEPTION_CATCHING=0")
	target_link_options(unit-test-libsinsp PRIVATE "-sALLOW_MEMORY_GROWTH=1")
	target_link_options(unit-test-libsinsp PRIVATE "-sEXPORTED_FUNCTIONS=['_main','_htons','_ntohs']")
	# note(jasondellaluce): since we run tests with node, we need to add this
	# for reading from local capture files.
	target_link_options(unit-test-libsinsp PRIVATE "-sNODERAWFS=1")
endif()

target_include_directories(unit-test-libsinsp
	PRIVATE
	${LIBS_DIR} # needed for driver/event_stats.h
	${CMAKE_CURRENT_BINARY_DIR} # needed for libsinsp_test_var.h.in
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(unit-test-libsinsp
	sinsp
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	"${TBB_LIB}"
)

if (CMAKE_BUILD_TYPE STREQUAL "Coverage")
	target_link_libraries(unit-test-libsinsp
		gcov
	)
endif()

# Add some additional include directories associated with `ADDITIONAL_SINSP_TESTS_SUITE`
# `ADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS` is a list of include paths `;` separated
if(ADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS)
	message(STATUS "- Additional include directories: ${ADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS}")
	target_include_directories(unit-test-libsinsp PRIVATE ${ADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS})
endif()

add_custom_target(run-unit-test-libsinsp
	DEPENDS unit-test-libsinsp
	COMMAND unit-test-libsinsp
)
