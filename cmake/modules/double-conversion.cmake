# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 The Falco Authors.
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

option(USE_BUNDLED_DOUBLE_CONVERSION "Enable building of the bundled double-conversion"
	   ${USE_BUNDLED_DEPS}
)

if(TARGET double-conversion OR TARGET double-conversion::double-conversion)
	# double-conversion already available (e.g. from parent or find_package)
elseif(NOT USE_BUNDLED_DOUBLE_CONVERSION)
	find_package(double-conversion REQUIRED)
else()
	# Disable tests for the bundled double-conversion
	set(BUILD_TESTING
		OFF
		CACHE BOOL "" FORCE
	)

	include(FetchContent)
	# Pin to v3.3.0: v3.4.0 requires CMake 3.29+ (project minimum is 3.24)
	FetchContent_Declare(
		double-conversion
		URL https://github.com/google/double-conversion/archive/refs/tags/v3.3.1.tar.gz
		URL_HASH SHA256=fe54901055c71302dcdc5c3ccbe265a6c191978f3761ce1414d0895d6b0ea90e
	)
	FetchContent_MakeAvailable(double-conversion)
endif()

# find_package(double-conversion) (e.g. vcpkg) provides double-conversion::double-conversion but not
# a target named "double-conversion". Add an alias so linkees can use either name.
if(TARGET double-conversion::double-conversion AND NOT TARGET double-conversion)
	add_library(double-conversion ALIAS double-conversion::double-conversion)
endif()
