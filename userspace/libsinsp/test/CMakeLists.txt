#
# Copyright (C) 2021 The Falco Authors.
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

include(jsoncpp)
include(gtest)
include(tbb)
if(NOT MINIMAL_BUILD)
	include(curl)
endif() # MINIMAL_BUILD

include_directories("..")
include_directories(${LIBSCAP_INCLUDE_DIR})

set(LIBSINSP_UNIT_TESTS_SOURCES
	cgroup_list_counter.ut.cpp
	sinsp.ut.cpp
	evttype_filter.ut.cpp
	token_bucket.ut.cpp
)

if(NOT MINIMAL_BUILD)
	list(APPEND LIBSINSP_UNIT_TESTS_SOURCES procfs_utils.ut.cpp)
endif()

add_executable(unit-test-libsinsp ${LIBSINSP_UNIT_TESTS_SOURCES})

target_link_libraries(unit-test-libsinsp
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	sinsp
)

add_custom_target(run-unit-test-libsinsp
	DEPENDS unit-test-libsinsp
	COMMAND unit-test-libsinsp
)
