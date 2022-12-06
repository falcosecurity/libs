include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)

# Include `libbpf` library.
include(libbpf RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
  message(FATAL_ERROR "problem with libbpf.cmake in ${CMAKE_MODULE_PATH}")
endif()

if(NOT MODERN_BPF_SKEL_DIR)
  # Directory in which the BPF skeleton will be built
  set(MODERN_BPF_SKEL_DIR "${CMAKE_BINARY_DIR}/skel_dir")
  file(MAKE_DIRECTORY ${MODERN_BPF_SKEL_DIR})
  # Build the BPF skeleton as custom target.
  add_subdirectory(${LIBSCAP_DIR}/driver/modern_bpf ${CMAKE_BINARY_DIR}/driver/modern_bpf)
else()
  set(USE_BUNDLED_MODERN_BPF OFF)
endif()
message(STATUS "USE_BUNDLED_MODERN_BPF: ${USE_BUNDLED_MODERN_BPF}, using skeleton dir: ${MODERN_BPF_SKEL_DIR}")

# Build `libpman` library.
add_subdirectory(${LIBSCAP_DIR}/userspace/libpman ${CMAKE_BINARY_DIR}/libpman)

add_library(scap_engine_modern_bpf
	scap_modern_bpf.c
)

add_dependencies(scap_engine_modern_bpf pman)
target_link_libraries(scap_engine_modern_bpf pman)
