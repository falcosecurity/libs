message(STATUS "Modern BPF tests build enabled")

include_directories(../userspace/common)

## Syscall_exit suite files.
file(GLOB_RECURSE SYSCALL_EXIT_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_exit_suite/*.cpp)

## Syscall_enter suite files.
file(GLOB_RECURSE SYSCALL_ENTER_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_enter_suite/*.cpp)

## Generic tracepoints suite files.
file(GLOB_RECURSE GENERIC_TRACEPOINTS_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/generic_tracepoints_suite/*.cpp)

## Local suite files. (Not enabled by default)
if(BUILD_ENHANCED_MODERN_BPF_TEST)
  file(GLOB_RECURSE LOCAL_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/local_suite/*.cpp)
endif()

set(MODERN_BPF_TEST_SOURCES
  ./start_tests.cpp
  ./event_class/event_class.cpp
  ./flags/capabilities.cpp
  ./helpers/proc_parsing.cpp
  "${SYSCALL_EXIT_TEST_SUITE}"
  "${SYSCALL_ENTER_TEST_SUITE}"
  "${GENERIC_TRACEPOINTS_TEST_SUITE}"
  "${LOCAL_TEST_SUITE}"
)

set(MODERN_BPF_TEST_INCLUDE
  PRIVATE
  "${GTEST_INCLUDE}"
  "${LIBSCAP_DIR}/driver/"
)

set(MODERN_BPF_TEST_LINK_LIBRARIES
  PRIVATE
  pman
  scap_event_schema
  "${GTEST_LIB}"
  "${GTEST_MAIN_LIB}"
)

set(MODERN_BPF_TEST_DEPENDECIES
  pman
)

if(USE_BUNDLED_GTEST)
  list(APPEND
    MODERN_BPF_TEST_DEPENDECIES
    gtest
  )
endif()

add_executable(bpf_test ${MODERN_BPF_TEST_SOURCES})
target_include_directories(bpf_test ${MODERN_BPF_TEST_INCLUDE})
target_link_libraries(bpf_test ${MODERN_BPF_TEST_LINK_LIBRARIES})
add_dependencies(bpf_test ${MODERN_BPF_TEST_DEPENDECIES})
