// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, SETRLIMIT_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 0;
	constexpr int64_t cur = 80;
	constexpr int64_t max = 81;
	constexpr uint8_t resource = 82;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_SETRLIMIT_X,
	                                      4,
	                                      return_value,
	                                      cur,
	                                      max,
	                                      resource);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the cur value is as expected.
	ASSERT_EQ(evt->get_param_by_name("cur")->as<int64_t>(), cur);

	// Check that the max value is as expected.
	ASSERT_EQ(evt->get_param_by_name("max")->as<int64_t>(), max);

	// Check that the resource value is as expected.
	ASSERT_EQ(evt->get_param_by_name("resource")->as<uint8_t>(), resource);
}
