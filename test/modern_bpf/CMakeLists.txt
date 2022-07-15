message(STATUS "Modern BPF tests build enabled")

## Syscall_exit suite files.
file(GLOB_RECURSE SYSCALL_EXIT_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_exit_suite/*.cpp)

## Syscall_enter suite files.
file(GLOB_RECURSE SYSCALL_ENTER_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_enter_suite/*.cpp)

set(MODERN_BPF_TEST_SOURCES
  ./start_tests.cpp
  ./event_class/event_class.cpp
  "${SYSCALL_EXIT_TEST_SUITE}"
  "${SYSCALL_ENTER_TEST_SUITE}"
)

set(MODERN_BPF_TEST_INCLUDE
  PRIVATE
  "${GTEST_INCLUDE}"
  "${CMAKE_SOURCE_DIR}/driver/"
)

set(MODERN_BPF_TEST_LINK_LIBRARIES 
  PRIVATE
  pman
  "${GTEST_LIB}"
  "${GTEST_MAIN_LIB}"
)

set(MODERN_BPF_TEST_DEPENDECIES 
  pman  
  gtest
)

add_executable(bpf_test ${MODERN_BPF_TEST_SOURCES})
target_include_directories(bpf_test ${MODERN_BPF_TEST_INCLUDE})
target_link_libraries(bpf_test ${MODERN_BPF_TEST_LINK_LIBRARIES})
add_dependencies(bpf_test ${MODERN_BPF_TEST_DEPENDECIES})
