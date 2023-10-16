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

if(NOT HAVE_LIBSINSP)
set(HAVE_LIBSINSP On)

if(NOT LIBSINSP_DIR)
	get_filename_component(LIBSINSP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

option(WITH_CHISEL "Include chisel implementation" OFF)

if(DEFINED LIBSINSP_USER_AGENT)
	add_definitions(-DLIBSINSP_USER_AGENT="${LIBSINSP_USER_AGENT}")
endif()

include(ExternalProject)
include(libscap)
if (NOT EMSCRIPTEN)
	include(tbb)
endif()
if(NOT WIN32 AND NOT APPLE)
	include(b64)
	include(jq)
endif()
if(NOT WIN32 AND NOT APPLE AND NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
	include(cares)
	include(curl)
endif()
include(jsoncpp)
include(valijson)
include(re2)
include(tinydir)

set(LIBSINSP_INCLUDE_DIRS ${LIBSINSP_DIR}/userspace/libsinsp ${LIBSCAP_INCLUDE_DIRS} ${DRIVER_CONFIG_DIR})
if(WITH_CHISEL)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${LIBSINSP_DIR}/userspace/chisel)
endif()

if (NOT EMSCRIPTEN)
	get_filename_component(TBB_ABSOLUTE_INCLUDE_DIR ${TBB_INCLUDE_DIR} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${TBB_ABSOLUTE_INCLUDE_DIR})
endif()

get_filename_component(JSONCPP_ABSOLUTE_INCLUDE_DIR ${JSONCPP_INCLUDE} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${JSONCPP_ABSOLUTE_INCLUDE_DIR})

get_filename_component(VALIJSON_ABSOLUTE_INCLUDE_DIR ${VALIJSON_INCLUDE} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${VALIJSON_ABSOLUTE_INCLUDE_DIR})

get_filename_component(RE2_ABSOLUTE_INCLUDE_DIR ${RE2_INCLUDE} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${RE2_ABSOLUTE_INCLUDE_DIR})

if(NOT MINIMAL_BUILD AND NOT EMSCRIPTEN AND NOT APPLE)
	get_filename_component(CARES_ABSOLUTE_INCLUDE_DIR ${CARES_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${CARES_ABSOLUTE_INCLUDE_DIR})
endif()

if(NOT WIN32 AND NOT APPLE)
	get_filename_component(B64_ABSOLUTE_INCLUDE_DIR ${B64_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${B64_ABSOLUTE_INCLUDE_DIR})
	get_filename_component(JQ_ABSOLUTE_INCLUDE_DIR ${JQ_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${JQ_ABSOLUTE_INCLUDE_DIR})
endif()

if(NOT WIN32 AND NOT APPLE AND NOT MINIMAL_BUILD AND NOT EMSCRIPTEN)
	get_filename_component(CURL_ABSOLUTE_INCLUDE_DIR ${CURL_INCLUDE_DIRS} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${CURL_ABSOLUTE_INCLUDE_DIR})
endif()

function(set_sinsp_target_properties target)
	set_target_properties(${target} PROPERTIES
		VERSION ${FALCOSECURITY_SHARED_LIBS_VERSION}
		SOVERSION ${FALCOSECURITY_SHARED_LIBS_SOVERSION}
	)
endfunction()

add_subdirectory(${LIBSINSP_DIR}/userspace/libsinsp ${CMAKE_BINARY_DIR}/libsinsp)
install(TARGETS sinsp
			ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			COMPONENT "sinsp")
install(DIRECTORY "${LIBSINSP_DIR}/userspace/libsinsp" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "sinsp"
			FILES_MATCHING PATTERN "*.h"
			PATTERN "*third_party*" EXCLUDE
			PATTERN "*examples*" EXCLUDE
			PATTERN "*doxygen*" EXCLUDE
			PATTERN "*scripts*" EXCLUDE
			PATTERN "*test*" EXCLUDE)
install(DIRECTORY "${LIBSINSP_DIR}/userspace/async" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "sinsp"
			FILES_MATCHING PATTERN "*.h")
if(WITH_CHISEL)
	install(DIRECTORY "${LIBSINSP_DIR}/userspace/chisel" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "sinsp"
			FILES_MATCHING PATTERN "*.h")
endif()
install(FILES ${PROJECT_BINARY_DIR}/libsinsp/libsinsp.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

endif()
