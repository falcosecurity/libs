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

include_directories("..")

set(LIBSCAP_UNIT_TESTS_SOURCES
    scap_event.ut.cpp
)

add_executable(unit-test-libscap ${LIBSCAP_UNIT_TESTS_SOURCES})

find_package(Threads)

target_link_libraries(unit-test-libscap
	"${CMAKE_THREAD_LIBS_INIT}"
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	scap
)

add_custom_target(run-unit-test-libscap
	DEPENDS unit-test-libscap
	COMMAND unit-test-libscap
)
