if(NOT HAVE_LIBSCAP)
set(HAVE_LIBSCAP On)

if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

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
	"${PROJECT_BINARY_DIR}/libscap/engine/bpf/libscap_engine_bpf.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/gvisor/libscap_engine_gvisor.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/kmod/libscap_engine_kmod.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/nodriver/libscap_engine_nodriver.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/noop/libscap_engine_noop.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/source_plugin/libscap_engine_source_plugin.a"
	"${PROJECT_BINARY_DIR}/libscap/engine/udig/libscap_engine_udig.a"
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
endif()
