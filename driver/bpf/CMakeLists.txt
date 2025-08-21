# SPDX-License-Identifier: GPL-2.0-only OR MIT
#
# Copyright (C) 2023 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See MIT.txt or GPL.txt for full copies
# of the license.
#

configure_file(../driver_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/../driver_config.h)

option(BUILD_BPF "Build the BPF driver on Linux" OFF)

if(BUILD_BPF)
	# Check minimum kernel version
	set(bpf_min_kver_map_x86_64 4.14)
	set(bpf_min_kver_map_aarch64 4.17)
	set(bpf_min_kver_map_s390x 5.5)
	set(bpf_min_kver_map_ppc64le 5.1)
	if(LINUX_KERNEL_VERSION VERSION_LESS ${bpf_min_kver_map_${TARGET_ARCH}})
		message(
			WARNING
				"[BPF] To run this driver you need a Linux kernel version >= ${bpf_min_kver_map_${TARGET_ARCH}} but actual kernel version is: ${UNAME_RESULT}"
		)
	endif()

	add_custom_target(
		bpf ALL
		COMMAND make
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different probe.o "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM
	)
endif()

set(BPF_SOURCES
	bpf_helpers.h
	builtins.h
	filler_helpers.h
	terminate_filler_helpers.h
	toctou_mitigation.h
	fillers.h
	Makefile
	maps.h
	plumbing_helpers.h
	probe.c
	quirks.h
	ring_helpers.h
	missing_definitions.h
	types.h
)

if(NOT DEFINED DRIVER_BPF_COMPONENT_NAME)
	set(DRIVER_BPF_COMPONENT_NAME ${DRIVER_COMPONENT_NAME})
endif()

# Append driver headers too since they are used by bpf headers
file(GLOB DRIVER_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/../*.h)
list(APPEND BPF_SOURCES ${DRIVER_HEADERS})

set(INSTALL_SET "")
# Copy all needed sources under src folder in current binary dir and add them to the set of
# installed files
foreach(SOURCE IN LISTS BPF_SOURCES)
	get_filename_component(FILENAME ${SOURCE} NAME)
	configure_file(${SOURCE} src/${FILENAME} COPYONLY)
	list(APPEND INSTALL_SET ${CMAKE_CURRENT_BINARY_DIR}/src/${FILENAME})
endforeach()

install(
	FILES ${INSTALL_SET}
	DESTINATION "src/${DRIVER_PACKAGE_NAME}-${DRIVER_VERSION}/bpf"
	COMPONENT ${DRIVER_BPF_COMPONENT_NAME}
)

#
# Copy all the "configure" modules
#
file(GLOB configure_modules "${CMAKE_CURRENT_SOURCE_DIR}/configure/*")
foreach(subdir ${configure_modules})
	if(IS_DIRECTORY "${subdir}")
		file(RELATIVE_PATH CONFIGURE_MODULE "${CMAKE_CURRENT_SOURCE_DIR}/configure" "${subdir}")
		configure_file(
			configure/${CONFIGURE_MODULE}/test.c src/configure/${CONFIGURE_MODULE}/test.c COPYONLY
		)
		configure_file(configure/Makefile src/configure/${CONFIGURE_MODULE}/Makefile COPYONLY)
		configure_file(configure/build.sh src/configure/${CONFIGURE_MODULE}/build.sh COPYONLY)
		configure_file(configure/Makefile.inc.in src/configure/${CONFIGURE_MODULE}/Makefile.inc)
		install(
			FILES "${CMAKE_CURRENT_BINARY_DIR}/src/configure/${CONFIGURE_MODULE}/build.sh"
				  "${CMAKE_CURRENT_BINARY_DIR}/src/configure/${CONFIGURE_MODULE}/test.c"
				  "${CMAKE_CURRENT_BINARY_DIR}/src/configure/${CONFIGURE_MODULE}/Makefile"
				  "${CMAKE_CURRENT_BINARY_DIR}/src/configure/${CONFIGURE_MODULE}/Makefile.inc"
			DESTINATION
				"src/${DRIVER_PACKAGE_NAME}-${DRIVER_VERSION}/bpf/configure/${CONFIGURE_MODULE}"
			COMPONENT ${DRIVER_BPF_COMPONENT_NAME}
		)
	endif()
endforeach()
