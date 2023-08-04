if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

# This should be renamed in `LIBS_DIR` not `LIBSCAP_DIR`
if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(GNUInstallDirs)

include(ExternalProject)

include(uthash)

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

set(LIBSCAP_INSTALL_LIBS)

# All of the targets in userspace/libscap
get_directory_property(libscap_subdirs DIRECTORY ${LIBSCAP_DIR}/userspace/libscap SUBDIRECTORIES)
set(libscap_subdir_targets)
foreach(libscap_subdir ${LIBSCAP_DIR}/userspace/libscap ${libscap_subdirs})
	get_directory_property(subdir_targets DIRECTORY ${libscap_subdir} BUILDSYSTEM_TARGETS)
	list(APPEND libscap_subdir_targets ${subdir_targets})
endforeach()

set(install_lib_type STATIC_LIBRARY)
if (BUILD_SHARED_LIBS)
	set(install_lib_type SHARED_LIBRARY)
endif()

# Installation targets only
foreach(libscap_subdir_target ${libscap_subdir_targets})
	get_target_property(cl_target_type ${libscap_subdir_target} TYPE)
	if (${cl_target_type} STREQUAL ${install_lib_type})
		list(APPEND LIBSCAP_INSTALL_LIBS ${libscap_subdir_target})
	endif()
endforeach()

# Installation targets and their dependencies
set(libscap_link_libraries)
foreach(libscap_install_lib ${LIBSCAP_INSTALL_LIBS})
	list(APPEND libscap_link_libraries ${libscap_install_lib})
	get_target_property(install_lib_link_libraries ${libscap_install_lib} LINK_LIBRARIES)
	foreach (install_lib_link_library ${install_lib_link_libraries})
		if (NOT ${install_lib_link_library} IN_LIST libscap_subdir_targets)
			list(APPEND libscap_link_libraries ${install_lib_link_library})
		endif()
	endforeach()
endforeach()
list(REMOVE_DUPLICATES libscap_link_libraries)

set(libscap_link_flags)
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
