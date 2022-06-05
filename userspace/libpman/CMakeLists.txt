
set(PMAN_SOURCES
    src/capture.c
    src/maps.c
    src/lifecycle.c
    src/programs.c
    src/ringbuffer.c
    src/configuration.c
    src/events_prog_names.c
    src/state.c
)

set(PMAN_PRIVATE_INCLUDES
    "${ZLIB_INCLUDES}"
    "${LIBBPF_INCLUDE}"
    "${SKEL_DIR}"
    "${CMAKE_SOURCE_DIR}/driver/" ## ppm_enum and tables
    "${CMAKE_SOURCE_DIR}/userspace/libscap" ## scap-stats struct
    "${CMAKE_SOURCE_DIR}/driver/modern_bpf/shared_definitions" ## bpf-shared structs
)

set(PMAN_PUBLIC_INCLUDES
    "./include"
)

add_library(pman ${PMAN_SOURCES})

target_include_directories(pman
    INTERFACE
    ${PMAN_PUBLIC_INCLUDES}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PMAN_PRIVATE_INCLUDES}
)

target_link_libraries(pman
    PRIVATE
    "${LIBBPF_LIB}"
    "${ZLIB_LIB}"
    elf
)

add_dependencies(pman ProbeSkeleton libbpf zlib)