include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
set(scap_engine_savefile_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/scap_savefile.c
    ${CMAKE_CURRENT_SOURCE_DIR}/scap_reader_gzfile.c
    ${CMAKE_CURRENT_SOURCE_DIR}/scap_reader_buffered.c)

if (BUILD_SHARED_LIBS)
    # Trying to build a shared scap_engine_savefile will result in circular
    # dependencies, so just add our sources to scap.
    target_sources(scap PRIVATE ${scap_engine_savefile_sources})
else()
    add_library(scap_engine_savefile ${scap_engine_savefile_sources})

    if(NOT MINIMAL_BUILD)
        add_dependencies(scap_engine_savefile zlib)
    endif()
    target_link_libraries(scap_engine_savefile scap_engine_noop scap_platform_util ${ZLIB_LIB})
    set_scap_target_properties(scap_engine_savefile)
endif()
