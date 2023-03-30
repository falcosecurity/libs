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

if(HAVE_STRLCPY)
	message(STATUS "Existing strlcpy found, will *not* use local definition")
else()
	message(STATUS "No strlcpy found, will use local definition")
endif()

configure_file(${LIBSCAP_DIR}/userspace/common/common_config.h.in ${PROJECT_BINARY_DIR}/common/common_config.h)
include_directories(${PROJECT_BINARY_DIR}/common)

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

get_filename_component(DRIVER_CONFIG_DIR ${CMAKE_BINARY_DIR}/driver/src ABSOLUTE)
get_filename_component(LIBSCAP_INCLUDE_DIR ${LIBSCAP_DIR}/userspace/libscap ABSOLUTE)
set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIR} ${DRIVER_CONFIG_DIR})

function(set_scap_target_properties target)
	set_target_properties(${target} PROPERTIES
		VERSION ${FALCOSECURITY_SHARED_LIBS_VERSION}
		SOVERSION ${FALCOSECURITY_SHARED_LIBS_SOVERSION}
	)
endfunction()

add_subdirectory(${LIBSCAP_DIR}/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)

# We can switch to using the MANUALLY_ADDED_DEPENDENCIES when our minimum
# CMake version is 3.8 or later.
set(LIBSCAP_LIBS
	scap
	scap_engine_noop
	scap_engine_source_plugin
	scap_error
	scap_event_schema)

set(libscap_conditional_libs
	driver_event_schema
	pman
	scap_engine_bpf
	scap_engine_gvisor
	scap_engine_kmod
	scap_engine_modern_bpf
	scap_engine_nodriver
	scap_engine_savefile
	scap_engine_udig
	scap_engine_util
	scap_platform)

foreach(libscap_conditional_lib ${libscap_conditional_libs})
	if(TARGET ${libscap_conditional_lib})
		list(APPEND LIBSCAP_LIBS ${libscap_conditional_lib})
	endif()
endforeach()

install(TARGETS ${LIBSCAP_LIBS}
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
endif()
