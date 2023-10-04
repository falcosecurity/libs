include(compute_versions RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
    message(FATAL_ERROR "problem with compute_versions.cmake in ${CMAKE_MODULE_PATH}")
endif()

set(DRIVER_CONFIG_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../driver)
get_filename_component(DRIVER_CONFIG_OUTPUT_DIR ${CMAKE_BINARY_DIR}/driver_config ABSOLUTE)

compute_versions(${DRIVER_CONFIG_SOURCE_DIR}/API_VERSION ${DRIVER_CONFIG_SOURCE_DIR}/SCHEMA_VERSION)
configure_file(${DRIVER_CONFIG_SOURCE_DIR}/driver_config.h.in ${DRIVER_CONFIG_OUTPUT_DIR}/driver_config.h.tmp)
execute_process(
        COMMAND ${CMAKE_COMMAND} -E copy_if_different driver_config.h.tmp driver_config.h
        WORKING_DIRECTORY ${DRIVER_CONFIG_OUTPUT_DIR}
)