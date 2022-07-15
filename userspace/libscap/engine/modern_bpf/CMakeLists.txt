include_directories(${LIBSCAP_INCLUDE_DIRS})

# Option to build bpf tests
option(BUILD_MODERN_BPF_TEST "Build tests for modern BPF" OFF)

# Add to libpman all functions related to the testing phase
if(BUILD_MODERN_BPF_TEST)
  add_definitions(-DTEST_HELPERS)
endif()

# Include `libbpf` library.
include(libbpf RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
  message(FATAL_ERROR "problem with libbpf.cmake in ${CMAKE_MODULE_PATH}")
endif()

# Directory in which the BPF skeleton will be built
set(SKEL_DIR "${CMAKE_BINARY_DIR}/skel_dir")
file(MAKE_DIRECTORY ${SKEL_DIR})

# Build the BPF skeleton as custom target.
add_subdirectory(${CMAKE_SOURCE_DIR}/driver/modern_bpf ${CMAKE_BINARY_DIR}/driver/modern_bpf)

# Build `libpman` library.
add_subdirectory(${CMAKE_SOURCE_DIR}/userspace/libpman ${CMAKE_BINARY_DIR}/libpman)

# Build modern BPF probe gtest
if(BUILD_MODERN_BPF_TEST)
  add_subdirectory(${CMAKE_SOURCE_DIR}/test/modern_bpf ${CMAKE_BINARY_DIR}/test/modern_bpf)
endif()

add_library(scap_engine_modern_bpf
	modern_bpf.c
)

add_dependencies(scap_engine_modern_bpf pman)
target_link_libraries(scap_engine_modern_bpf pman)
