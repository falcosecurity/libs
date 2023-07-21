if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

# This should be renamed in `LIBS_DIR` not `LIBSCAP_DIR`
if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(GNUInstallDirs)

include(ExternalProject)

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)
check_symbol_exists(strlcat "string.h" HAVE_STRLCAT)

if(HAVE_STRLCPY)
	message(STATUS "Existing strlcpy found, will *not* use local definition")
else()
	message(STATUS "No strlcpy found, will use local definition")
endif()

if(HAVE_STRLCAT)
	message(STATUS "Existing strlcat found, will *not* use local definition")
else()
	message(STATUS "No strlcat found, will use local definition")
endif()

configure_file(${LIBSCAP_DIR}/userspace/common/common_config.h.in ${PROJECT_BINARY_DIR}/common/common_config.h)
include_directories(${PROJECT_BINARY_DIR}/common)

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	get_filename_component(DRIVER_CONFIG_DIR ${CMAKE_BINARY_DIR}/driver/src ABSOLUTE)
else()
	# This doesn't install all of the driver headers but seems to be sufficient for
	# non-Linux platforms.
	get_filename_component(DRIVER_CONFIG_DIR ${PROJECT_SOURCE_DIR}/driver ABSOLUTE)
endif()

get_filename_component(LIBSCAP_INCLUDE_DIR ${LIBSCAP_DIR}/userspace/libscap ABSOLUTE)
set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIR} ${DRIVER_CONFIG_DIR})

function(set_scap_target_properties target)
	set_target_properties(${target} PROPERTIES
		VERSION ${FALCOSECURITY_SHARED_LIBS_VERSION}
		SOVERSION ${FALCOSECURITY_SHARED_LIBS_SOVERSION}
	)
endfunction()

add_subdirectory(${LIBSCAP_DIR}/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)

set(LIBSCAP_INSTALL_LIBS scap)

# "Conditional" means it might not exist or it might be static.
# We might be able to automate this using the proposed ALL_BUILDSYSTEM_TARGETS:
# https://gitlab.kitware.com/cmake/cmake/-/issues/20124
set(libscap_conditional_libs
	driver_event_schema
	pman
	scap_engine_bpf
	scap_engine_gvisor
	scap_engine_kmod
	scap_engine_modern_bpf
	scap_engine_nodriver
	scap_engine_noop
	scap_engine_savefile
	scap_engine_source_plugin
	scap_engine_test_input
	scap_engine_udig
	scap_engine_util
	scap_error
	scap_event_schema
	scap_platform
	scap_platform_util)

# Installation targets
foreach(libscap_conditional_lib ${libscap_conditional_libs})
	if(TARGET ${libscap_conditional_lib})
		get_target_property(cl_target_type ${libscap_conditional_lib} TYPE)
		if (NOT ${BUILD_SHARED_LIBS} OR ${cl_target_type} STREQUAL SHARED_LIBRARY)
			list(APPEND LIBSCAP_INSTALL_LIBS ${libscap_conditional_lib})
		endif()
	endif()
endforeach()

# Installation targets and their dependencies
set(libscap_link_libraries)
foreach(libscap_install_lib ${LIBSCAP_INSTALL_LIBS})
	list(APPEND libscap_link_libraries ${libscap_install_lib})
	get_target_property(install_lib_link_libraries ${libscap_install_lib} LINK_LIBRARIES)
	foreach (install_lib_link_library ${install_lib_link_libraries})
		if (NOT ${install_lib_link_library} IN_LIST libscap_conditional_libs)
			list(APPEND libscap_link_libraries ${install_lib_link_libraries})
		endif()
	endforeach()
endforeach()
list(REMOVE_DUPLICATES libscap_link_libraries)

set(libscap_link_flags "")
foreach(libscap_link_library ${libscap_link_libraries})
	list(APPEND libscap_link_flags "-l${libscap_link_library}")
endforeach()

string(REPLACE ";" " " LIBSCAP_LINK_LIBRARIES_FLAGS "${libscap_link_flags}")
configure_file(${LIBSCAP_DIR}/userspace/libscap/libscap.pc.in ${PROJECT_BINARY_DIR}/libscap/libscap.pc @ONLY)

install(TARGETS ${LIBSCAP_INSTALL_LIBS}
			ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			COMPONENT "scap" OPTIONAL)
install(DIRECTORY "${LIBSCAP_INCLUDE_DIR}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h"
			PATTERN "*examples*" EXCLUDE
			PATTERN "*doxygen*" EXCLUDE)
install(DIRECTORY "${DRIVER_CONFIG_DIR}/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/driver"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h")
install(DIRECTORY "${LIBSCAP_DIR}/userspace/common" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h")
install(DIRECTORY "${PROJECT_BINARY_DIR}/common" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h")
install(DIRECTORY "${LIBSCAP_DIR}/userspace/plugin" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/userspace"
		COMPONENT "scap"
		FILES_MATCHING PATTERN "*.h")
install(FILES ${PROJECT_BINARY_DIR}/libscap/libscap.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
