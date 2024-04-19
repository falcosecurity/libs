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

# Computes API/SCHEMA major, minor, patch and git commit
macro(compute_versions api_version_path schema_version_path)
    
    # API VERSION
    file(STRINGS ${api_version_path} DRIVER_API_VERSION LIMIT_COUNT 1)
    string(REGEX MATCHALL "[0-9]+" DRIVER_API_COMPONENTS "${DRIVER_API_VERSION}")
    list(GET DRIVER_API_COMPONENTS 0 PPM_API_CURRENT_VERSION_MAJOR)
    list(GET DRIVER_API_COMPONENTS 1 PPM_API_CURRENT_VERSION_MINOR)
    list(GET DRIVER_API_COMPONENTS 2 PPM_API_CURRENT_VERSION_PATCH)
    message(STATUS "Driver API version ${PPM_API_CURRENT_VERSION_MAJOR}.${PPM_API_CURRENT_VERSION_MINOR}.${PPM_API_CURRENT_VERSION_PATCH}")

    # SCHEMA VERSION
    file(STRINGS ${schema_version_path} DRIVER_SCHEMA_VERSION LIMIT_COUNT 1)
    string(REGEX MATCHALL "[0-9]+" DRIVER_SCHEMA_COMPONENTS "${DRIVER_SCHEMA_VERSION}")
    list(GET DRIVER_SCHEMA_COMPONENTS 0 PPM_SCHEMA_CURRENT_VERSION_MAJOR)
    list(GET DRIVER_SCHEMA_COMPONENTS 1 PPM_SCHEMA_CURRENT_VERSION_MINOR)
    list(GET DRIVER_SCHEMA_COMPONENTS 2 PPM_SCHEMA_CURRENT_VERSION_PATCH)
    message(STATUS "Driver schema version ${PPM_SCHEMA_CURRENT_VERSION_MAJOR}.${PPM_SCHEMA_CURRENT_VERSION_MINOR}.${PPM_SCHEMA_CURRENT_VERSION_PATCH}")

    # GIT COMMIT
    if(NOT DEFINED GIT_COMMIT)
        execute_process(COMMAND git rev-parse HEAD OUTPUT_VARIABLE GIT_COMMIT ERROR_QUIET WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    string(STRIP "${GIT_COMMIT}" GIT_COMMIT)
endmacro()
