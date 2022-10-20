include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_bpf scap_bpf.c)
if(NOT MINIMAL_BUILD)

set(LIBELF "elf")
# With `BUNDLED_DEPS`, we enforce the usage of a static library
if(USE_BUNDLED_DEPS)
    find_static_library("elf" LIBELF)
endif()

target_link_libraries(scap_engine_bpf scap_event_schema scap_engine_util ${LIBELF})
endif()
