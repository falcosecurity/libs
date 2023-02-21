include_directories(${LIBSCAP_INCLUDE_DIRS})
add_library(scap_engine_udig scap_udig.c)
target_link_libraries(scap_engine_udig scap_engine_util scap_error)
if(UNIX AND NOT APPLE)
    target_link_libraries(scap_engine_udig rt)
endif()

set_scap_target_properties(scap_engine_udig)
