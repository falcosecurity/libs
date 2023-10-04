#
# Copyright (C) 2022 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

include(driver_config)

option(BUILD_BPF "Build the BPF driver on Linux" OFF)

# Note: probe.c *must* be the first entry to generate a proper Makefile
set(BPF_SOURCES
	probe.c
	bpf_helpers.h
	builtins.h
	filler_helpers.h
	fillers.h
	maps.h
	missing_definitions.h
	plumbing_helpers.h
	quirks.h
	ring_helpers.h
	types.h
	${DRIVER_CONFIG_OUTPUT_DIR}/driver_config.h
	../ppm_api_version.h
	../ppm_events_public.h
	../feature_gates.h
	../ppm_version.h
	../ppm_fillers.h
	../ppm_flag_helpers.h
	../ppm.h
	../ppm_consumer.h
	../capture_macro.h
	../systype_compat.h
	)

if(BUILD_BPF)
	# Check minimum kernel version
	set(bpf_min_kver_map_x86_64 4.14)
	set(bpf_min_kver_map_aarch64 4.17)
	set(bpf_min_kver_map_s390x 5.5)
	if (LINUX_KERNEL_VERSION VERSION_LESS ${bpf_min_kver_map_${TARGET_ARCH}})
		message(WARNING "[BPF] To run this driver you need a Linux kernel version >= ${bpf_min_kver_map_${TARGET_ARCH}} but actual kernel version is: ${UNAME_RESULT}")
	endif()

	foreach(FILENAME IN LISTS BPF_SOURCES)
		get_filename_component(BASENAME ${FILENAME} NAME)
		configure_file(${FILENAME} src/${BASENAME} COPYONLY)
		string(APPEND BPF_DEPENDENCIES "$(src)/${BASENAME} ")
	endforeach()

	add_custom_target(bpf ALL
		COMMAND make
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different probe.o "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/src"
		VERBATIM)
endif()

install(FILES
	${BPF_SOURCES}
	Makefile
	DESTINATION "src/${DRIVER_PACKAGE_NAME}-${DRIVER_VERSION}/bpf"
	COMPONENT ${DRIVER_COMPONENT_NAME})
