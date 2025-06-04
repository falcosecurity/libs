
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

TEST_F(sinsp_with_test_input, FUTEX_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	uint64_t addr = 0x5600C32351E0;
	uint16_t op = 129;
	uint64_t val = 1;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_FUTEX_X,
	                                      4,
	                                      return_value,
	                                      addr,
	                                      op,
	                                      val);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the address value is as expected.
	ASSERT_EQ(evt->get_param_by_name("addr")->as<uint64_t>(), addr);

	// Check that the op value is as expected.
	ASSERT_EQ(evt->get_param_by_name("op")->as<uint16_t>(), op);

	// Check that the op value is as expected.
	ASSERT_EQ(evt->get_param_by_name("val")->as<uint64_t>(), val);
}
