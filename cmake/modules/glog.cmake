# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
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

option(USE_BUNDLED_GLOG "Enable building of the bundled glog" ${USE_BUNDLED_DEPS})

if(TARGET glog OR TARGET glog::glog)
	# glog already available
elseif(NOT USE_BUNDLED_GLOG)
	find_package(glog REQUIRED)
else()
	set(BUILD_TESTING
		OFF
		CACHE BOOL "" FORCE
	)
	set(WITH_GFLAGS
		OFF
		CACHE BOOL "" FORCE
	)
	set(WITH_GTEST
		OFF
		CACHE BOOL "" FORCE
	)
	set(WITH_UNWIND
		none
		CACHE STRING "" FORCE
	)
	set(BUILD_SHARED_LIBS
		OFF
		CACHE BOOL "" FORCE
	)

	include(FetchContent)
	FetchContent_Declare(
		glog
		GIT_REPOSITORY https://github.com/google/glog.git
		GIT_TAG v0.7.1
	)
	FetchContent_MakeAvailable(glog)
endif()

if(NOT TARGET glog AND NOT TARGET glog::glog)
	add_custom_target(glog)
endif()
