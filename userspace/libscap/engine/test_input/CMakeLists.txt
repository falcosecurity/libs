include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_test_input test_input.c test_input_platform.c)
target_link_libraries(scap_engine_test_input scap_engine_noop scap_platform_util)

set_scap_target_properties(scap_engine_test_input)
