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

option(USE_BUNDLED_JSONCPP "Enable building of the bundled jsoncpp" ${USE_BUNDLED_DEPS})

if(JSONCPP_INCLUDE AND JSONCPP_LIB)
	message(STATUS "Using jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
elseif(NOT USE_BUNDLED_JSONCPP)
	find_path(JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
	find_library(JSONCPP_LIB NAMES jsoncpp)
	if(JSONCPP_INCLUDE AND JSONCPP_LIB)
		message(STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jsoncpp")
	endif()
else()
	set(JSONCPP_SRC "${PROJECT_BINARY_DIR}/jsoncpp-prefix/src")
	if(BUILD_SHARED_LIBS)
		set(JSONCPP_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(JSONCPP_STATIC_OPTION "-DBUILD_STATIC_LIBS=Off")
	else()
		set(JSONCPP_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(JSONCPP_STATIC_OPTION)
	endif()
	set(JSONCPP_INCLUDE "${JSONCPP_SRC}/include/")
	if(NOT WIN32)
		set(JSONCPP_LIB "${JSONCPP_SRC}/lib/libjsoncpp${JSONCPP_LIB_SUFFIX}")
	else()
		set(JSONCPP_LIB "${JSONCPP_SRC}/lib/jsoncpp${JSONCPP_LIB_SUFFIX}")
	endif()

	if(NOT TARGET jsoncpp)
		message(STATUS "Using bundled jsoncpp in '${JSONCPP_SRC}'")
		if(NOT WIN32)
			ExternalProject_Add(
					jsoncpp
					PREFIX "${PROJECT_BINARY_DIR}/jsoncpp-prefix"
					URL "https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/1.9.5.tar.gz"
					URL_HASH
					"SHA256=f409856e5920c18d0c2fb85276e24ee607d2a09b5e7d5f0a371368903c275da2"
					CMAKE_ARGS
						-DBUILD_OBJECT_LIBS=Off
						${JSONCPP_STATIC_OPTION}
						-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						-DJSONCPP_WITH_TESTS=Off
						-DJSONCPP_WITH_POST_BUILD_UNITTEST=Off
						-DCMAKE_INSTALL_PREFIX=${JSONCPP_SRC}
						-DCMAKE_INSTALL_LIBDIR=lib
					BUILD_BYPRODUCTS ${JSONCPP_LIB}
			)
		else()
			# see: https://cmake.org/cmake/help/latest/policy/CMP0091.html
			if(CMAKE_VERSION VERSION_LESS 3.15.0)
				ExternalProject_Add(
						jsoncpp
						PREFIX "${PROJECT_BINARY_DIR}/jsoncpp-prefix"
						URL "https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/1.9.5.tar.gz"
						URL_HASH
						"SHA256=f409856e5920c18d0c2fb85276e24ee607d2a09b5e7d5f0a371368903c275da2"
						CMAKE_ARGS
						-DCMAKE_CXX_FLAGS_DEBUG=${FALCOSECURITY_LIBS_DEBUG_FLAGS}
						-DCMAKE_CXX_FLAGS_RELEASE=${FALCOSECURITY_LIBS_RELEASE_FLAGS}
						-DBUILD_OBJECT_LIBS=Off
						${JSONCPP_STATIC_OPTION}
						-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						-DJSONCPP_WITH_TESTS=Off
						-DJSONCPP_WITH_POST_BUILD_UNITTEST=Off
						-DCMAKE_INSTALL_PREFIX=${JSONCPP_SRC}
						-DCMAKE_INSTALL_LIBDIR=lib
				)
			else()
				ExternalProject_Add(
						jsoncpp
						PREFIX "${PROJECT_BINARY_DIR}/jsoncpp-prefix"
						URL "https://github.com/open-source-parsers/jsoncpp/archive/refs/tags/1.9.5.tar.gz"
						URL_HASH
						"SHA256=f409856e5920c18d0c2fb85276e24ee607d2a09b5e7d5f0a371368903c275da2"
						CMAKE_ARGS
						-DCMAKE_POLICY_DEFAULT_CMP0091:STRING=NEW
						-DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
						-DBUILD_OBJECT_LIBS=Off
						${JSONCPP_STATIC_OPTION}
						-DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
						-DJSONCPP_WITH_TESTS=Off
						-DJSONCPP_WITH_POST_BUILD_UNITTEST=Off
						-DCMAKE_INSTALL_PREFIX=${JSONCPP_SRC}
						-DCMAKE_INSTALL_LIBDIR=lib
				)
			endif()
		endif()

		install(FILES "${JSONCPP_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${JSONCPP_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()
endif()

if(NOT TARGET jsoncpp)
	add_custom_target(jsoncpp)
endif()

include_directories("${JSONCPP_INCLUDE}")
