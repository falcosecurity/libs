
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

TEST_F(sinsp_with_test_input, FLOCK_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	int64_t fd = 10;
	uint32_t operation = 1;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_FLOCK_X,
	                                      3,
	                                      return_value,
	                                      fd,
	                                      operation);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);

	// Check that the operation value is as expected.
	ASSERT_EQ(evt->get_param_by_name("operation")->as<uint32_t>(), operation);
}
