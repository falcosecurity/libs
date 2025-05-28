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

TEST_F(sinsp_with_test_input, PTRACE_parse_ptrace_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	std::vector<uint8_t> addr = test_utils::pack_ptrace_pair(PPM_PTRACE_IDX_UINT64, 0xcafeabba);
	std::vector<uint8_t> data = test_utils::pack_ptrace_pair(PPM_PTRACE_IDX_UINT64, 0xabbacaffe);
	uint16_t request = PPM_PTRACE_PEEKSIGINFO;
	int64_t pid = 66;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_PTRACE_X,
	                                      5,
	                                      return_value,
	                                      scap_const_sized_buffer{addr.data(), addr.size()},
	                                      scap_const_sized_buffer{data.data(), data.size()},
	                                      request,
	                                      pid);

	// we want to check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// we want to check that the address is as expected.
	ASSERT_EQ(evt->get_param_by_name("addr")->as<std::vector<uint8_t>>(), addr);

	// we want to check that the data is as expected.
	ASSERT_EQ(evt->get_param_by_name("data")->as<std::vector<uint8_t>>(), data);

	// we want to check that the request type is as expected.
	ASSERT_EQ(evt->get_param_by_name("request")->as<uint16_t>(), request);

	// we want to check that the pid value is as expected.
	ASSERT_EQ(evt->get_param_by_name("pid")->as<int64_t>(), pid);
}
