# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

option(USE_BUNDLED_NJSON "Enable building of the bundled nlohmann-json" ${USE_BUNDLED_DEPS})

if(NJSON_INCLUDE)
    # we already have nlohmann-json
elseif(NOT USE_BUNDLED_NJSON)
    find_path(NJSON_INCLUDE nlohmann/json.hpp PATH_SUFFIXES nlohmann)
    if(NJSON_INCLUDE)
        message(STATUS "Found nlohmann-json: include: ${NJSON_INCLUDE}")
    else()
        message(FATAL_ERROR "Couldn't find system nlohmann-json")
    endif()
else()
    set(NJSON_SRC "${PROJECT_BINARY_DIR}/njson-prefix/src/njson")
    set(NJSON_INCLUDE "${NJSON_SRC}/include")

    message(STATUS "Using bundled nlohmann-json in '${NJSON_SRC}'")

    if(NOT TARGET njson)
        ExternalProject_Add(njson
            PREFIX "${PROJECT_BINARY_DIR}/njson-prefix"
            URL https://github.com/nlohmann/json/archive/v3.11.3.tar.gz
            URL_HASH SHA256=0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406
            CONFIGURE_COMMAND ""
            CMAKE_ARGS
                -DCMAKE_BUILD_TYPE=Release
                -DJSON_BuildTests=OFF
            BUILD_COMMAND ""
            INSTALL_COMMAND "")
    endif()
endif()

if(NOT TARGET njson)
    add_custom_target(njson)
endif()

include_directories("${NJSON_INCLUDE}")