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

if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

if(NOT LIBS_DIR)
	get_filename_component(LIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
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

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	get_filename_component(DRIVER_CONFIG_DIR ${CMAKE_BINARY_DIR}/driver/src ABSOLUTE)
else()
	# This doesn't install all of the driver headers but seems to be sufficient for
	# non-Linux platforms.
	get_filename_component(DRIVER_CONFIG_DIR ${PROJECT_SOURCE_DIR}/driver ABSOLUTE)
endif()

get_filename_component(LIBSCAP_INCLUDE_DIR ${LIBS_DIR}/userspace/libscap ABSOLUTE)
set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIR} ${PROJECT_BINARY_DIR} ${DRIVER_CONFIG_DIR})

function(set_scap_target_properties target)
	set_target_properties(${target} PROPERTIES
		VERSION ${FALCOSECURITY_SHARED_LIBS_VERSION}
		SOVERSION ${FALCOSECURITY_SHARED_LIBS_SOVERSION}
	)
endfunction()

add_subdirectory(${LIBS_DIR}/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)

set(LIBSCAP_INSTALL_LIBS)

# All of the targets in userspace/libscap
get_directory_property(libscap_subdirs DIRECTORY ${LIBS_DIR}/userspace/libscap SUBDIRECTORIES)
set(libscap_subdir_targets)
foreach(libscap_subdir ${LIBS_DIR}/userspace/libscap ${libscap_subdirs})
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
set(libscap_link_libdirs)
foreach(libscap_install_lib ${LIBSCAP_INSTALL_LIBS})
	list(APPEND libscap_link_libraries ${libscap_install_lib})
	get_target_property(install_lib_link_libraries ${libscap_install_lib} LINK_LIBRARIES)
	foreach (install_lib_link_library ${install_lib_link_libraries})
		if (NOT ${install_lib_link_library} IN_LIST libscap_subdir_targets)
			if(${install_lib_link_library} MATCHES "/")
				# We have a path. Convert it to -L<dir> + -l<lib>.
				get_filename_component(scap_lib_dir ${install_lib_link_library} DIRECTORY)
				list(APPEND libscap_link_libdirs -L${scap_lib_dir})
				get_filename_component(scap_lib_base ${install_lib_link_library} NAME_WE)
				string(REGEX REPLACE "^lib" "" scap_lib_base ${scap_lib_base})
				list(APPEND libscap_link_libraries ${scap_lib_base})
			else()
				list(APPEND libscap_link_libraries ${install_lib_link_library})
			endif()
		endif()
	endforeach()
endforeach()
list(REMOVE_DUPLICATES libscap_link_libraries)

set(libscap_link_flags)
foreach(libscap_link_library ${libscap_link_libraries})
	list(APPEND libscap_link_flags "-l${libscap_link_library}")
endforeach()

string(REPLACE ";" " " LIBSCAP_LINK_LIBRARIES_FLAGS "${libscap_link_flags}")
string(REPLACE ";" " " LIBSCAP_LINK_LIBDIRS_FLAGS "${libscap_link_libdirs}")
configure_file(${LIBS_DIR}/userspace/libscap/libscap.pc.in ${PROJECT_BINARY_DIR}/libscap/libscap.pc @ONLY)

install(TARGETS ${LIBSCAP_INSTALL_LIBS}
			ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			COMPONENT "scap" OPTIONAL)
install(DIRECTORY "${LIBSCAP_INCLUDE_DIR}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h"
			PATTERN "*examples*" EXCLUDE
			PATTERN "*doxygen*" EXCLUDE)
install(DIRECTORY "${DRIVER_CONFIG_DIR}/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/driver"
			COMPONENT "scap"
			FILES_MATCHING PATTERN "*.h")
install(DIRECTORY "${LIBS_DIR}/userspace/plugin" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
		COMPONENT "scap"
		FILES_MATCHING PATTERN "*.h")
install(FILES ${PROJECT_BINARY_DIR}/libscap/scap_config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/libscap)
install(FILES ${PROJECT_BINARY_DIR}/libscap/scap_strl_config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}/libscap)
install(FILES ${PROJECT_BINARY_DIR}/libscap/libscap.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
