#
# Copyright (C) 2022 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_DRIVER "Build the driver on Linux" ON)
option(ENABLE_DKMS "Enable DKMS on Linux" ON)
if(NOT DEFINED DRIVER_COMPONENT_NAME)
    set(DRIVER_COMPONENT_NAME "scap-driver")
endif()

# The driver build process is somewhat involved because we use the same
# sources for building the driver locally and for shipping as a DKMS module.
#
# We need a single directory with the following files inside:
# - all the driver *.c/*.h sources
# - Makefile generated from Makefile.in
# - driver_config.h generated from driver_config.h.in
#
# The Makefile _must_ be called just Makefile (and not e.g. Makefile.dkms)
# because of the module build process, which looks like this:
# 1. The user (or some script) runs make in our driver directory
# 2. Our Makefile runs the Makefile from kernel sources/headers
# 3. The kernel Makefile calls our original Makefile again, with options that
#    trigger the actual build. This step cannot know that our Makefile has
#    a different name.
#
# (DKMS needs a Makefile called Makefile as well).
#
# The files need to be in a single directory because we cannot know where
# the sources will be built (especially by DKMS) so we cannot put _any_ paths
# in the Makefile.
#
# The chosen directory must not be ${CMAKE_CURRENT_BINARY_DIR} because CMake
# puts its own generated Makefile in there, so we (arbitrarily) choose
# ${CMAKE_CURRENT_BINARY_DIR}/src. To maintain compatibility with older versions,
# after the build we copy the compiled module one directory up,
# to ${CMAKE_CURRENT_BINARY_DIR}.

file(STRINGS API_VERSION DRIVER_API_VERSION LIMIT_COUNT 1)
string(REGEX MATCHALL "[0-9]+" DRIVER_API_COMPONENTS "${DRIVER_API_VERSION}")
list(GET DRIVER_API_COMPONENTS 0 PPM_API_CURRENT_VERSION_MAJOR)
list(GET DRIVER_API_COMPONENTS 1 PPM_API_CURRENT_VERSION_MINOR)
list(GET DRIVER_API_COMPONENTS 2 PPM_API_CURRENT_VERSION_PATCH)
message(STATUS "Driver API version ${PPM_API_CURRENT_VERSION_MAJOR}.${PPM_API_CURRENT_VERSION_MINOR}.${PPM_API_CURRENT_VERSION_PATCH}")

file(STRINGS SCHEMA_VERSION DRIVER_SCHEMA_VERSION LIMIT_COUNT 1)
string(REGEX MATCHALL "[0-9]+" DRIVER_SCHEMA_COMPONENTS "${DRIVER_SCHEMA_VERSION}")
list(GET DRIVER_SCHEMA_COMPONENTS 0 PPM_SCHEMA_CURRENT_VERSION_MAJOR)
list(GET DRIVER_SCHEMA_COMPONENTS 1 PPM_SCHEMA_CURRENT_VERSION_MINOR)
list(GET DRIVER_SCHEMA_COMPONENTS 2 PPM_SCHEMA_CURRENT_VERSION_PATCH)
message(STATUS "Driver schema version ${PPM_SCHEMA_CURRENT_VERSION_MAJOR}.${PPM_SCHEMA_CURRENT_VERSION_MINOR}.${PPM_SCHEMA_CURRENT_VERSION_PATCH}")

execute_process(COMMAND git rev-parse HEAD OUTPUT_VARIABLE GIT_COMMIT ERROR_QUIET WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
string(STRIP "${GIT_COMMIT}" GIT_COMMIT)

configure_file(dkms.conf.in src/dkms.conf)
configure_file(Makefile.in src/Makefile)
configure_file(driver_config.h.in src/driver_config.h)

# Find m4 executable to compile our syscall_table.m4 script into syscall_table.c
find_program(M4_EXECUTABLE m4 DOC "The M4 macro processor" )
if(NOT M4_EXECUTABLE)
	message(FATAL_ERROR "Failed to find the M4 macro processor." )
endif()
execute_process(COMMAND ${M4_EXECUTABLE} syscall_table.m4
		OUTPUT_FILE syscall_table.c
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set(DRIVER_SOURCES
	dynamic_params_table.c
	event_table.c
	fillers_table.c
	flags_table.c
	kernel_hacks.h
	main.c
	ppm.h
	ppm_api_version.h
	ppm_events.c
	ppm_events.h
	ppm_events_public.h
	ppm_fillers.c
	ppm_fillers.h
	ppm_flag_helpers.h
	ppm_ringbuffer.h
	ppm_syscall.h
	ppm_cputime.c
	ppm_compat_unistd_32.h
	ppm_version.h
	systype_compat.h
)

foreach(FILENAME IN LISTS DRIVER_SOURCES)
	configure_file(${FILENAME} src/${FILENAME} COPYONLY)
endforeach()

# make can be self-referenced as $(MAKE) only from Makefiles but this
# triggers syntax errors with other generators such as Ninja
if(${CMAKE_GENERATOR} STREQUAL "Unix Makefiles")
	set(MAKE_COMMAND "$(MAKE)")
else()
	set(MAKE_COMMAND "make")
endif()

# This if/else is needed because you currently cannot manipulate dependencies
# of built-in targets like "all" in CMake:
# http://public.kitware.com/Bug/view.php?id=8438
if(BUILD_DRIVER)
	add_custom_target(driver ALL
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${DRIVER_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM)
else()
	add_custom_target(driver
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${DRIVER_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY src
		VERBATIM)
endif()

add_custom_target(install_driver
	COMMAND ${MAKE_COMMAND} install
	DEPENDS driver
	WORKING_DIRECTORY src
	VERBATIM)

if(ENABLE_DKMS)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/src/Makefile
		${CMAKE_CURRENT_BINARY_DIR}/src/dkms.conf
		${CMAKE_CURRENT_BINARY_DIR}/src/driver_config.h
		${DRIVER_SOURCES}
		DESTINATION "src/${DRIVER_PACKAGE_NAME}-${DRIVER_VERSION}"
		COMPONENT ${DRIVER_COMPONENT_NAME})

endif()

add_subdirectory(bpf)
