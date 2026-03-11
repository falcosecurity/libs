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

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})
include(libbpf)

option(BPF_ITERATOR_DEBUG "Enable debug logging for BPF iterator event parsing" OFF)
option(BPF_ITERATOR_DEBUG_RAW "Enable printing raw events (requires BPF_ITERATOR_DEBUG)" ON)
option(BPF_ITERATOR_DEBUG_PARSED "Enable printing parsed data (requires BPF_ITERATOR_DEBUG)" ON)

add_library(
	pman
	src/stats.c
	src/maps.c
	src/lifecycle.c
	src/programs.c
	src/ringbuffer.c
	src/configuration.c
	src/state.c
	src/sc_set.c
	src/events_prog_table.c
	src/iterators.c
	src/support_probing.c
)

target_include_directories(
	pman
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
			$<BUILD_INTERFACE:${LIBS_DIR}> # ppm_enum and tables
			$<BUILD_INTERFACE:${LIBS_DIR}/userspace> # scap-stats struct
			${ZLIB_INCLUDE}
			${MODERN_BPF_SKEL_DIR}
)

target_link_libraries(pman PUBLIC scap_event_schema scap_platform lbpf ${ZLIB_LIB})

if(BPF_ITERATOR_DEBUG)
	target_compile_definitions(pman PRIVATE BPF_ITERATOR_DEBUG=1)
	if(BPF_ITERATOR_DEBUG_RAW)
		target_compile_definitions(pman PRIVATE BPF_ITERATOR_DEBUG_RAW=1)
	endif()
	if(BPF_ITERATOR_DEBUG_PARSED)
		target_compile_definitions(pman PRIVATE BPF_ITERATOR_DEBUG_PARSED=1)
	endif()
endif()

if(TARGET ProbeSkeleton)
	add_dependencies(pman ProbeSkeleton)
endif()

install(
	TARGETS pman
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			COMPONENT "scap"
			OPTIONAL
)

install(FILES include/libpman.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

file(RELATIVE_PATH PKGCONFIG_RELATIVE_PREFIX
	 ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig ${CMAKE_INSTALL_PREFIX}
)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libpman.pc.in ${PROJECT_BINARY_DIR}/libpman.pc @ONLY)

install(FILES ${PROJECT_BINARY_DIR}/libpman.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
