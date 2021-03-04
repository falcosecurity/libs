#
# Copyright (C) 2021 The Falco Authors
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

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)
if (CREATE_TEST_TARGETS AND NOT WIN32)
  option(USE_BUNDLED_GTEST "Enable building of the bundled gtest" ${USE_BUNDLED_DEPS})
  if (NOT USE_BUNDLED_GTEST)
    find_path(GTEST_INCLUDE_DIR PATH_SUFFIXES gtest NAMES gtest.h)
    find_library(GTEST_LIB NAMES gtest)
    find_library(GTEST_MAIN_LIB NAMES gtest_main)
    if (GTEST_INCLUDE_DIR AND GTEST_LIB AND GTEST_MAIN_LIB)
      message(STATUS "Found gtest: include: ${GTEST_INCLUDE_DIR}, lib: ${GTEST_LIB}, main lib: ${GTEST_MAIN_LIB}")
    else ()
      message(FATAL_ERROR "Couldn't find system gtest")
    endif ()
  else ()
    # https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
    # Download and unpack googletest at configure time
    configure_file(CMakeListsGtestInclude.cmake googletest-download/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
      RESULT_VARIABLE result
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
    if (result)
      message(FATAL_ERROR "CMake step for googletest failed: ${result}")
    endif ()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
      RESULT_VARIABLE result
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
    if (result)
      message(FATAL_ERROR "Build step for googletest failed: ${result}")
    endif ()

    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
      ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
      EXCLUDE_FROM_ALL)

    set(GTEST_INCLUDE_DIR "${gtest_SOURCE_DIR}/include/gtest")
    set(GTEST_MAIN_LIB "gtest_main")
  endif ()
endif () # NOT WIN32