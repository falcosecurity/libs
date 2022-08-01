include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_savefile scap_reader.c scap_savefile.c)
target_link_libraries(scap_engine_savefile scap_engine_noop)
