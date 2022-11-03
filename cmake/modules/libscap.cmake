if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

# This should be renamed in `LIBS_DIR` not `LIBSCAP_DIR`
if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

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

add_subdirectory(${LIBSCAP_DIR}/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)

set(LIBSCAP_LIBS "")
list(APPEND LIBSCAP_LIBS
	"${PROJECT_BINARY_DIR}/libscap/libscap.a"
	"${PROJECT_BINARY_DIR}/libscap/libscap_engine_util.a"
	"${PROJECT_BINARY_DIR}/libscap/libscap_event_schema.a"
	"${PROJECT_BINARY_DIR}/libscap/libdriver_event_schema.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/bpf/libscap_engine_bpf.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/gvisor/libscap_engine_gvisor.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/kmod/libscap_engine_kmod.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/nodriver/libscap_engine_nodriver.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/noop/libscap_engine_noop.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/savefile/libscap_engine_savefile.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/source_plugin/libscap_engine_source_plugin.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/udig/libscap_engine_udig.a"
if(BUILD_LIBSCAP_MODERN_BPF)
	"${PROJECT_BINARY_DIR}/libscap/engine/modern_bpf/libscap_engine_modern_bpf.a"
	"${PROJECT_BINARY_DIR}/libpman/libpman.a"
endif()
)
install(FILES ${LIBSCAP_LIBS} DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
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
