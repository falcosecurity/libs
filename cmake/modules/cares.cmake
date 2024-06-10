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

option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})

if(CARES_INCLUDE)
	# we already have c-ares
elseif(NOT USE_BUNDLED_CARES)
	find_path(CARES_INCLUDE NAMES cares/ares.h ares.h)
	find_library(CARES_LIB NAMES cares)
	if(CARES_INCLUDE AND CARES_LIB)
		message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system c-ares")
	endif()
else()
	if(BUILD_SHARED_LIBS)
		set(CARES_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
		set(CARES_CPPFLAGS )
		set(CARES_STATIC_OPTION )
	else()
		set(CARES_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
		set(CARES_CPPFLAGS -DCARES_STATICLIB)
		set(CARES_STATIC_OPTION --disable-shared)
	endif()
	set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
	set(CARES_INCLUDE "${CARES_SRC}/target/include/")
	set(CARES_LIB "${CARES_SRC}/target/lib/libcares${CARES_LIB_SUFFIX}")
	set(CARES_INSTALL_DIR "${CARES_SRC}/target")

	if(NOT TARGET c-ares)
		if(NOT ENABLE_PIC)
			set(CARES_PIC_OPTION )
		else()
			set(CARES_PIC_OPTION "--with-pic=yes")
		endif()

		message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
		ExternalProject_Add(c-ares
			PREFIX "${PROJECT_BINARY_DIR}/c-ares-prefix"
			URL "https://github.com/c-ares/c-ares/releases/download/v1.30.0/c-ares-1.30.0.tar.gz"
			URL_HASH "SHA256=4fea312112021bcef081203b1ea020109842feb58cd8a36a3d3f7e0d8bc1138c"
			CONFIGURE_COMMAND CPPFLAGS=${CARES_CPPFLAGS} ./configure ${CARES_STATIC_OPTION} ${CARES_PIC_OPTION} --prefix=${CARES_INSTALL_DIR}
			BUILD_COMMAND make
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
			INSTALL_COMMAND make install)
		install(FILES "${CARES_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
		install(DIRECTORY "${CARES_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
				COMPONENT "libs-deps")
	endif()

endif()

if(NOT TARGET c-ares)
	add_custom_target(c-ares)
endif()

include_directories("${CARES_INCLUDE}")
