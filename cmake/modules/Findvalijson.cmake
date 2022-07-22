#
# Copyright (C) 2022 The Falco Authors.
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

# This module is used to find where the valijson headers are installed
# on the system. This is required up to v0.6, since package config
# files are not provided. This is fixed in master though, and this
# file shall be automatically ignored for later versions.

find_path(VALIJSON_INCLUDE NAMES valijson/validator.hpp validator.hpp)

if (VALIJSON_INCLUDE)
    if (NOT valijson_FIND_QUIETLY)
        message(STATUS "Found valijson: include: ${VALIJSON_INCLUDE}.")
    endif()
else()
    if (valijson_FIND_REQUIRED)
        message(FATAL_ERROR "Required component valijson missing.")
    endif()
    if (NOT valijson_FIND_QUIETLY)
        message(WARNING "Valijson not found.")
    endif()
endif()
