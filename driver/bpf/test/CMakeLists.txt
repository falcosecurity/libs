#
# Copyright (c) 2021 The Falco Authors
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_BPF_TEST "Build the tests for the BPF driver on Linux" OFF)
option(BPF_TEST_DEBUG "Enable debug mode for the BPF driver tests" OFF)

if (BUILD_BPF_TEST)
  message(STATUS "BPF tests build enabled")

  set(FILLER_TESTS
    test_renameat2.cpp)

  set(BPF_TEST_SOURCES
    runner.cpp
    filler_test.cpp
    probe_loader.c
    "${FILLER_TESTS}"
    "${PROJECT_BINARY_DIR}/driver/src/fillers_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/syscall_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/event_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/flags_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/dynamic_params_table.c")

  set(BPF_TEST_INCLUDES "${ZLIB_INCLUDE}"
    "${LIBBPF_INCLUDE}"
    "${PROJECT_BINARY_DIR}/driver/src"
    "${PROJECT_BINARY_DIR}/userspace"
    "${GTEST_INCLUDE_DIR}")

  set(BPF_TEST_LINK_LIBRARIES elf rt "${LIBBPF_LIB}" "${ZLIB_LIB}" "${GTEST_LIB}" "${GTEST_MAIN_LIB}")

  # Test against the classic BPF probe
  add_executable(test_fillers_bpf
    ${BPF_TEST_SOURCES})

  add_dependencies(test_fillers_bpf libbpf zlib)

  target_include_directories(
    test_fillers_bpf
    PUBLIC
    ${BPF_TEST_INCLUDES}
  )
  target_link_libraries(test_fillers_bpf ${BPF_TEST_LINK_LIBRARIES})

  if (BPF_TEST_DEBUG)
    message(STATUS "BPF test debug mode enabled")
    add_definitions(-DBPF_TEST_DEBUG)
  endif ()


endif ()
