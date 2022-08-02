include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_savefile
    scap_savefile.c
    scap_reader_gzfile.c
    scap_reader_buffered.c)
target_link_libraries(scap_engine_savefile scap_engine_noop)
