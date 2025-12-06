# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

option(USE_BUNDLED_GTEST "Enable building of the bundled gtest" ${USE_BUNDLED_DEPS})

if(GTEST_INCLUDE_DIR)
	# we already have gtest
elseif(NOT USE_BUNDLED_GTEST)
	find_package(GTest REQUIRED)
else()
	include(FetchContent)
	FetchContent_Declare(
		gtest
		URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.tar.gz
		URL_HASH SHA256=78c676fc63881529bf97bf9d45948d905a66833fbfa5318ea2cd7478cb98f399
		OVERRIDE_FIND_PACKAGE
	)
	FetchContent_MakeAvailable(gtest)
endif()

if(NOT TARGET gtest)
	add_custom_target(gtest)
endif()
