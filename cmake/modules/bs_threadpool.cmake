# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

#
# bshoshany/thread-pool (https://github.com/bshoshany/thread-pool)
#

option(USE_BUNDLED_BS_THREADPOOL "Enable building of the bundled bs_threadpool" ${USE_BUNDLED_DEPS})

if(BS_THREADPOOL_INCLUDE)
	# we already have bs_threadpool
elseif(NOT USE_BUNDLED_BS_THREADPOOL)
	find_package(bs_threadpool REQUIRED)
else()
	set(BS_THREADPOOL_SRC "${PROJECT_BINARY_DIR}/bs_threadpool-prefix/src/bs_threadpool")
	set(BS_THREADPOOL_INCLUDE "${BS_THREADPOOL_SRC}/include")

	message(STATUS "Using bundled bs_threadpool in '${BS_THREADPOOL_SRC}'")

	ExternalProject_Add(
		bs_threadpool
		PREFIX "${PROJECT_BINARY_DIR}/bs_threadpool-prefix"
		URL "https://github.com/bshoshany/thread-pool/archive/refs/tags/v4.1.0.tar.gz"
		URL_HASH "SHA256=be7abecbc420bb87919eeef729b13ff7c29d5ce547bdae284923296c695415bd"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND ""
	)
endif()

if(NOT TARGET bs_threadpool)
	add_custom_target(bs_threadpool)
endif()

include_directories("${BS_THREADPOOL_INCLUDE}")
