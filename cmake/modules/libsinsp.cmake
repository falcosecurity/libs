if(NOT HAVE_LIBSINSP)
set(HAVE_LIBSINSP On)

if(NOT LIBSINSP_DIR)
	get_filename_component(LIBSINSP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

option(WITH_CHISEL "Include chisel implementation" OFF)

if(DEFINED LIBSINSP_USER_AGENT)
	add_definitions(-DLIBSINSP_USER_AGENT="${LIBSINSP_USER_AGENT}")
endif()

include(ExternalProject)
include(libscap)
if(NOT WIN32)
	include(tbb)
endif()
if(NOT WIN32 AND NOT APPLE)
	include(b64)
	include(jq)
	include(curl)
endif()
include(jsoncpp)
if(NOT MINIMAL_BUILD)
	include(cares)
endif()

set(LIBSINSP_INCLUDE_DIRS ${LIBSINSP_DIR}/userspace/libsinsp ${LIBSINSP_DIR}/common ${LIBSCAP_INCLUDE_DIRS} ${DRIVER_CONFIG_DIR})
if(WITH_CHISEL)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${LIBSINSP_DIR}/userspace/chisel)
endif()

if(NOT WIN32)
	get_filename_component(TBB_ABSOLUTE_INCLUDE_DIR ${TBB_INCLUDE_DIR} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${TBB_ABSOLUTE_INCLUDE_DIR})
endif()

get_filename_component(JSONCPP_ABSOLUTE_INCLUDE_DIR ${JSONCPP_INCLUDE} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${JSONCPP_ABSOLUTE_INCLUDE_DIR})
if(NOT MINIMAL_BUILD)
	get_filename_component(CARES_ABSOLUTE_INCLUDE_DIR ${CARES_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${CARES_ABSOLUTE_INCLUDE_DIR})
endif()

if(NOT WIN32 AND NOT APPLE)
	get_filename_component(B64_ABSOLUTE_INCLUDE_DIR ${B64_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${B64_ABSOLUTE_INCLUDE_DIR})
	get_filename_component(JQ_ABSOLUTE_INCLUDE_DIR ${JQ_INCLUDE} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${JQ_ABSOLUTE_INCLUDE_DIR})
	get_filename_component(CURL_ABSOLUTE_INCLUDE_DIR ${CURL_INCLUDE_DIR} ABSOLUTE)
	list(APPEND LIBSINSP_INCLUDE_DIRS ${CURL_ABSOLUTE_INCLUDE_DIR})
endif()


add_subdirectory(${LIBSINSP_DIR}/userspace/libsinsp ${CMAKE_BINARY_DIR}/libsinsp)

endif()
