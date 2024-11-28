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

if(NOT HAVE_LIBSINSP)
	set(HAVE_LIBSINSP On)

	if(NOT LIBS_DIR)
		get_filename_component(LIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
	endif()

	option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)
	option(ENABLE_THREAD_POOL "Enable inspector thread pool" OFF)

	if(DEFINED LIBSINSP_USER_AGENT)
		add_definitions(-DLIBSINSP_USER_AGENT="${LIBSINSP_USER_AGENT}")
	endif()

	include(ExternalProject)
	include(libscap)
	if(NOT EMSCRIPTEN)
		include(tbb)
	endif()
	if(NOT WIN32
	   AND NOT APPLE
	   AND NOT MINIMAL_BUILD
	   AND NOT EMSCRIPTEN
	)
		include(cares)
	endif()
	include(jsoncpp)
	include(valijson)
	include(re2)

	if(ENABLE_THREAD_POOL AND NOT EMSCRIPTEN)
		include(bs_threadpool)
	endif()

	set(LIBSINSP_INCLUDE_DIRS)

	if(NOT USE_BUNDLED_TBB AND NOT EMSCRIPTEN)
		list(APPEND LIBSINSP_INCLUDE_DIRS ${TBB_INCLUDE_DIR})
	endif()

	if(NOT USE_BUNDLED_JSONCPP)
		list(APPEND LIBSINSP_INCLUDE_DIRS ${JSONCPP_INCLUDE})
	endif()

	function(set_sinsp_target_properties target)
		set_target_properties(
			${target} PROPERTIES VERSION ${FALCOSECURITY_SHARED_LIBS_VERSION}
								 SOVERSION ${FALCOSECURITY_SHARED_LIBS_SOVERSION}
		)
	endfunction()

	add_subdirectory(${LIBS_DIR}/userspace/libsinsp ${CMAKE_BINARY_DIR}/libsinsp)
	install(
		TARGETS sinsp
		ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT "sinsp"
	)
	install(
		DIRECTORY "${LIBS_DIR}/userspace/libsinsp"
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "sinsp"
		FILES_MATCHING
		PATTERN "*.h"
		PATTERN "*third_party*" EXCLUDE
		PATTERN "*examples*" EXCLUDE
		PATTERN "*doxygen*" EXCLUDE
		PATTERN "*scripts*" EXCLUDE
		PATTERN "*test*" EXCLUDE
	)
	install(
		DIRECTORY "${LIBS_DIR}/userspace/async"
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "sinsp"
		FILES_MATCHING
		PATTERN "*.h"
	)
	install(FILES ${PROJECT_BINARY_DIR}/libsinsp/libsinsp.pc
			DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
	)

endif()
