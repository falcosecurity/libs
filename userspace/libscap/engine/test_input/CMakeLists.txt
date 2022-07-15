include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_test_input test_input.c)
target_link_libraries(scap_engine_test_input scap_engine_noop)
