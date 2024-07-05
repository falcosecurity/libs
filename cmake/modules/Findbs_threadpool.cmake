# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

find_path(BS_THREADPOOL_INCLUDE NAMES BS_thread_pool.hpp)

if (BS_THREADPOOL_INCLUDE)
    if (NOT bs_threadpool_FIND_QUIETLY)
        message(STATUS "Found bs_threadpool: include: ${BS_THREADPOOL_INCLUDE}.")
    endif()
else()
    if (bs_threadpool_FIND_REQUIRED)
        message(FATAL_ERROR "Required component bs_threadpool missing.")
    endif()
    if (NOT bs_threadpool_FIND_QUIETLY)
        message(WARNING "bs_threadpool not found.")
    endif()
endif()