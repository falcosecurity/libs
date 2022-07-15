
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
    "${CMAKE_SOURCE_DIR}/driver/modern_bpf/" ## bpf-shared structs
)

set(PMAN_PUBLIC_INCLUDES
    "./include"
)

set(PMAN_PRIVATE_LINK_LIBRARIES
    "${LIBBPF_LIB}"
    "${ZLIB_LIB}"
    scap_event_schema
    elf
)

set(PMAN_DEPENDENCIES
    ProbeSkeleton
)

if(USE_BUNDLED_LIBBPF)
list(APPEND 
    PMAN_DEPENDENCIES
    libbpf
)
endif()

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
    ${PMAN_PRIVATE_LINK_LIBRARIES}
)

add_dependencies(pman ${PMAN_DEPENDENCIES})