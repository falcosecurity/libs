include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_test_input test_input.c)

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
    add_dependencies(scap_engine_test_input zlib)
endif()

target_link_libraries(scap_engine_test_input scap_engine_noop)
