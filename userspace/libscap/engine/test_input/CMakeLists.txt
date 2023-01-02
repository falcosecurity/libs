include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_test_input test_input.c)
add_dependencies(scap_engine_test_input zlib)
target_link_libraries(scap_engine_test_input scap_engine_noop)
