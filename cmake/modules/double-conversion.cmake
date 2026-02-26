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
	FetchContent_Declare(
		double-conversion
		GIT_REPOSITORY https://github.com/google/double-conversion.git
		GIT_TAG v3.4.0
	)
	FetchContent_MakeAvailable(double-conversion)
endif()

if(NOT TARGET double-conversion)
	add_custom_target(double-conversion)
endif()
