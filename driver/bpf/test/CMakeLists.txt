#
# Copyright (c) 2013-2021 Sysdig Inc.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_BPF_TEST "Build the tests for the BPF driver on Linux" OFF)
option(BPF_TEST_DEBUG "Enable debug mode for the BPF driver tests" OFF)

if (BUILD_BPF_TEST)
  message(STATUS "BPF tests build enabled")

  set(BPF_TEST_SOURCES
    test_renameat2.cpp
    test_fillers.c
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

  add_dependencies(test_fillers_bpf libbpf zlib bpf)

  target_include_directories(
    test_fillers_bpf
    PUBLIC
    ${BPF_TEST_INCLUDES}
  )
  target_link_libraries(test_fillers_bpf ${BPF_TEST_LINK_LIBRARIES})
  target_compile_definitions(test_fillers_bpf PUBLIC -DPROBE_PATH=${BPF_PROBE_PATH})

  # Test against the BPF probe + BTF
  add_executable(test_fillers_bpf_btf
    ${BPF_TEST_SOURCES})
  add_dependencies(test_fillers_bpf_btf libbpf zlib bpf)

  target_include_directories(
    test_fillers_bpf_btf
    PUBLIC
    ${BPF_TEST_INCLUDES}
  )
  target_link_libraries(test_fillers_bpf_btf ${BPF_TEST_LINK_LIBRARIES})
  target_compile_definitions(test_fillers_bpf_btf PUBLIC -DPROBE_PATH=${BPF_PROBE_PATH})

  # Test against the BPF probe + BTF + CO-RE
  add_executable(test_fillers_bpf_btf_core
    ${BPF_TEST_SOURCES})

  add_dependencies(test_fillers_bpf_btf_core libbpf zlib bpf)

  target_include_directories(
    test_fillers_bpf_btf_core
    PUBLIC
    ${BPF_TEST_INCLUDES}
  )
  target_link_libraries(test_fillers_bpf_btf_core ${BPF_TEST_LINK_LIBRARIES})
  target_compile_definitions(test_fillers_bpf_btf_core PUBLIC -DPROBE_PATH=${BPF_PROBE_PATH})

  if (BPF_TEST_DEBUG)
    message(STATUS "BPF test debug mode enabled")
    add_definitions(-DBPF_TEST_DEBUG)
  endif ()


endif ()
