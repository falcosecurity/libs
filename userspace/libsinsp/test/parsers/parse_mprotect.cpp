
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

TEST_F(sinsp_with_test_input, MPROTECT_parse) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 0;
	constexpr uint64_t addr = 66;
	constexpr uint64_t length = 67;
	constexpr uint32_t prot = 68;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_MPROTECT_X,
	                                      4,
	                                      return_value,
	                                      addr,
	                                      length,
	                                      prot);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the addr value is as expected.
	ASSERT_EQ(evt->get_param_by_name("addr")->as<uint64_t>(), addr);
	// Check that the length value is as expected.
	ASSERT_EQ(evt->get_param_by_name("length")->as<uint64_t>(), length);
	// Check that the prot value is as expected.
	ASSERT_EQ(evt->get_param_by_name("prot")->as<uint32_t>(), prot);
}
