add_executable(unit-test-libscap-linux test_fds.c)

target_link_libraries(unit-test-libscap-linux "${GTEST_LIB}" "${GTEST_MAIN_LIB}" scap)

add_test(NAME unit-test-libscap-linux COMMAND unit-test-libscap-linux)
