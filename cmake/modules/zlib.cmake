#
# Copyright (C) 2021 The Falco Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

if(WIN32 OR NOT MINIMAL_BUILD)
  if(NOT USE_BUNDLED_ZLIB)
    find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
    find_library(ZLIB_LIB NAMES z)
    if(ZLIB_INCLUDE AND ZLIB_LIB)
      message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
    else()
      message(FATAL_ERROR "Couldn't find system zlib")
    endif()
  else()
    set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
    message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
    set(ZLIB_INCLUDE "${ZLIB_SRC}")
    if(NOT WIN32)
      set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
      ExternalProject_Add(zlib
        URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
        URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
        CONFIGURE_COMMAND "./configure"
        BUILD_COMMAND ${CMD_MAKE}
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${ZLIB_LIB}
        INSTALL_COMMAND "")
    else()
      set(ZLIB_LIB "${ZLIB_SRC}/zdll.lib")
      ExternalProject_Add(zlib
        URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
        URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND nmake -f win32/Makefile.msc
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${ZLIB_LIB}
        INSTALL_COMMAND "")
    endif()

  endif()
endif() # MINIMAL_BUILD
