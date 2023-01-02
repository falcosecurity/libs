message(STATUS "Drivers tests build enabled")

## Syscall_exit suite files.
file(GLOB_RECURSE SYSCALL_EXIT_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_exit_suite/*.cpp)

## Syscall_enter suite files.
file(GLOB_RECURSE SYSCALL_ENTER_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_enter_suite/*.cpp)

## Generic tracepoints suite files.
file(GLOB_RECURSE GENERIC_TRACEPOINTS_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/generic_tracepoints_suite/*.cpp)

## Actions suite files
file(GLOB_RECURSE ACTIONS_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/actions_suite/*.cpp)

set(DRIVERS_TEST_SOURCES
  ./start_tests.cpp
  ./event_class/event_class.cpp
  ./flags/capabilities.cpp
  ./helpers/proc_parsing.cpp
  "${SYSCALL_EXIT_TEST_SUITE}"
  "${SYSCALL_ENTER_TEST_SUITE}"
  "${GENERIC_TRACEPOINTS_TEST_SUITE}"
  "${ACTIONS_TEST_SUITE}"
)

set(DRIVERS_TEST_INCLUDE
  PRIVATE
  ../../userspace/common
  "${GTEST_INCLUDE}"
  "${LIBSCAP_DIR}/driver/"
  "${LIBSCAP_DIR}/userspace/libscap"
)

set(DRIVERS_TEST_LINK_LIBRARIES
  scap
  "${GTEST_LIB}"
  "${GTEST_MAIN_LIB}"
)

set(DRIVERS_TEST_DEPENDECIES
  scap
  gtest
)

add_executable(drivers_test ${DRIVERS_TEST_SOURCES})
target_include_directories(drivers_test ${DRIVERS_TEST_INCLUDE})
target_link_libraries(drivers_test ${DRIVERS_TEST_LINK_LIBRARIES})
add_dependencies(drivers_test ${DRIVERS_TEST_DEPENDECIES})
