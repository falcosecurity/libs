include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_savefile
    scap_savefile.c
    scap_reader_gzfile.c
    scap_reader_buffered.c)

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
    add_dependencies(scap_engine_savefile zlib)
endif()

target_link_libraries(scap_engine_savefile scap_engine_noop)
