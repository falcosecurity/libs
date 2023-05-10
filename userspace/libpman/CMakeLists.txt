set(PMAN_SOURCES
    src/stats.c
    src/maps.c
    src/lifecycle.c
    src/programs.c
    src/ringbuffer.c
    src/configuration.c
    src/state.c
    src/sc_set.c
)

set(PMAN_PRIVATE_INCLUDES
    "${ZLIB_INCLUDE}"
    "${LIBBPF_INCLUDE}"
    "${MODERN_BPF_SKEL_DIR}"
    "${LIBELF_INCLUDE}"
    "${LIBSCAP_DIR}/driver/" ## ppm_enum and tables
    "${LIBSCAP_DIR}/userspace/libscap" ## scap-stats struct
    "${LIBSCAP_DIR}/driver/modern_bpf/" ## bpf-shared structs
)

set(PMAN_PUBLIC_INCLUDES
    "./include"
)

set(PMAN_LINK_LIBRARIES
    "${LIBBPF_LIB}"
    "${LIBELF_LIB}"
    "${ZLIB_LIB}"
    scap_event_schema
    scap_platform
)

set(PMAN_DEPENDENCIES scap_platform)

if(USE_BUNDLED_MODERN_BPF)
    list(APPEND
        PMAN_DEPENDENCIES
        ProbeSkeleton
    )
endif()

if(USE_BUNDLED_LIBBPF)
    list(APPEND
        PMAN_DEPENDENCIES
        libbpf
    )
endif()

add_library(pman ${PMAN_SOURCES})

target_include_directories(pman
    PUBLIC
    ${PMAN_PUBLIC_INCLUDES}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PMAN_PRIVATE_INCLUDES}
)

target_link_libraries(pman
    PUBLIC
    ${PMAN_LINK_LIBRARIES}
)

add_dependencies(pman ${PMAN_DEPENDENCIES})
set(LIBPMAN_PREFIX "[LIBPMAN]")
message(STATUS "${LIBPMAN_PREFIX} LIBSCAP_TESTS_SOURCES: ${PMAN_SOURCES}")
message(STATUS "${LIBPMAN_PREFIX} LIBSCAP_TESTS_INCLUDE: ${PMAN_PRIVATE_INCLUDES}")
message(STATUS "${LIBPMAN_PREFIX} LIBSCAP_TESTS_LIBRARIES: ${PMAN_LINK_LIBRARIES}")
message(STATUS "${LIBPMAN_PREFIX} LIBSCAP_TESTS_DEPENDENCIES: ${PMAN_DEPENDENCIES}")
