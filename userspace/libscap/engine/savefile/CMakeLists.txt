include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)

# Since we have circular dependencies between libscap and the savefile engine,
# make this library always static (directly linked into libscap)
add_library(scap_engine_savefile
    STATIC
    scap_savefile.c
    scap_reader_gzfile.c
    scap_reader_buffered.c)

target_link_libraries(scap_engine_savefile scap_engine_noop scap_platform_util)

if(NOT MINIMAL_BUILD)
    add_dependencies(scap_engine_savefile zlib)
    target_link_libraries(scap_engine_savefile ${ZLIB_LIB})
endif()