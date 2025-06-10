
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
#include <vector>

TEST_F(sinsp_with_test_input, POLL_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 55;
	const std::vector<uint8_t> fds{0x1, 0x0, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};
	constexpr int64_t timeout = 1000;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_POLL_X,
	                                      3,
	                                      return_value,
	                                      scap_const_sized_buffer{fds.data(), fds.size()},
	                                      timeout);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the fds value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fds")->as<std::vector<uint8_t>>(), fds);

	// Check that the timeout value is as expected.
	ASSERT_EQ(evt->get_param_by_name("timeout")->as<int64_t>(), timeout);
}
