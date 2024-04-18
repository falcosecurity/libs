message(STATUS "Drivers tests build enabled")

## Configure ia32 action test
option(ENABLE_IA32_TESTS "Enable ia32 tests. Require ia32 glibc and gcc." ON)
if(ENABLE_IA32_TESTS)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test_suites/actions_suite/ia32.cpp.in ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/actions_suite/ia32.cpp)
endif()

## Syscall_exit suite files.
file(GLOB_RECURSE SYSCALL_EXIT_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_exit_suite/*.cpp)

## Syscall_enter suite files.
file(GLOB_RECURSE SYSCALL_ENTER_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/syscall_enter_suite/*.cpp)

## Generic tracepoints suite files.
file(GLOB_RECURSE GENERIC_TRACEPOINTS_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/generic_tracepoints_suite/*.cpp)

## Actions suite files
file(GLOB_RECURSE ACTIONS_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/actions_suite/*.cpp)

include(libscap)

set(DRIVERS_TEST_SOURCES
  ./start_tests.cpp
  ./event_class/event_class.cpp
  ./flags/capabilities.cpp
  ./helpers/proc_parsing.cpp
  ./helpers/file_opener.cpp
  "${SYSCALL_EXIT_TEST_SUITE}"
  "${SYSCALL_ENTER_TEST_SUITE}"
  "${GENERIC_TRACEPOINTS_TEST_SUITE}"
  "${ACTIONS_TEST_SUITE}"
)

set(DRIVERS_TEST_INCLUDE
  PRIVATE
  "${GTEST_INCLUDE}"
  "${LIBS_DIR}/driver/"
  "${LIBSCAP_INCLUDE_DIRS}"
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

## IA32 tests are only available on x86_64
if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64" AND ENABLE_IA32_TESTS)
    add_executable(ia32 ./helpers/ia32.c)
    set_target_properties(ia32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
    set(DRIVERS_TEST_DEPENDECIES
            ${DRIVERS_TEST_DEPENDECIES}
            ia32
    )
endif()

add_compile_options(${FALCOSECURITY_LIBS_USERSPACE_COMPILE_FLAGS})
add_link_options(${FALCOSECURITY_LIBS_USERSPACE_LINK_FLAGS})
add_executable(drivers_test ${DRIVERS_TEST_SOURCES})
target_include_directories(drivers_test ${DRIVERS_TEST_INCLUDE})
target_link_libraries(drivers_test ${DRIVERS_TEST_LINK_LIBRARIES})
add_dependencies(drivers_test ${DRIVERS_TEST_DEPENDECIES})


