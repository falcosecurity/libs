# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

message(STATUS "Libsinsp unit e2e tests build enabled")

if(NOT DEFINED DRIVER_NAME)
    set(DRIVER_NAME "scap")
endif()

# Create a libsinsp_test_var.h file with some variables used by our tests
# for example the kmod path or the bpf path.
configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/libsinsp_test_var.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libsinsp_test_var.h"
)

add_executable(libsinsp_e2e_tests
    event_capture.cpp
    main.cpp
    subprocess.cpp
    sys_call_test.cpp
)

if(BUILD_BPF)
    add_dependencies(libsinsp_e2e_tests driver bpf)
else()
    add_dependencies(libsinsp_e2e_tests driver)
endif()

target_link_libraries(libsinsp_e2e_tests
    sinsp
    GTest::gtest
    pthread
)

target_include_directories(libsinsp_e2e_tests
    PRIVATE
    ${PROJECT_BINARY_DIR}/driver/src
    "${CMAKE_CURRENT_BINARY_DIR}" # used to include `libsinsp_test_var.h`
)

add_executable(test_helper test_helper.cpp)

target_link_libraries(test_helper pthread)

add_executable(vtidcollision vtidcollision.c)

execute_process(
    COMMAND "uname" "-m"
    OUTPUT_VARIABLE ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    # Build 32-bit tests only for architectures where that is supported
    if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        add_executable(test_helper_32 test_helper.cpp)
        set_target_properties(test_helper_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
        install(
            TARGETS test_helper_32
            DESTINATION ${CMAKE_INSTALL_PREFIX}/test
            COMPONENT libsinsp_e2e_tests
        )
        target_link_libraries(test_helper_32 pthread)
    endif()
endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")

install(
    DIRECTORY
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/captures
    COMPONENT libsinsp_e2e_tests
)

install(
    DIRECTORY
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources/run
    COMPONENT libsinsp_e2e_tests
)

install(
    TARGETS test_helper vtidcollision
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT libsinsp_e2e_tests
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test_helper.sh ${CMAKE_CURRENT_BINARY_DIR}/test_helper.sh COPYONLY
)

install(
    FILES test_helper.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
    COMPONENT libsinsp_e2e_tests
)

install(
    TARGETS libsinsp_e2e_tests
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT libsinsp_e2e_tests
)
