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

TEST_F(sinsp_with_test_input, MMAP2_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 139631788478464;
	constexpr uint32_t vm_size = 5908;
	constexpr uint32_t vm_rss = 1024;
	constexpr uint32_t vm_swap = 0;
	constexpr uint64_t addr = 0;
	constexpr uint64_t length = 139264;
	constexpr uint32_t prot = 3;
	constexpr uint32_t flags = 10;
	constexpr int64_t fd = -1;
	constexpr uint64_t pgoffset = 0;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_MMAP2_X,
	                                      10,
	                                      return_value,
	                                      vm_size,
	                                      vm_rss,
	                                      vm_swap,
	                                      addr,
	                                      length,
	                                      prot,
	                                      flags,
	                                      fd,
	                                      pgoffset);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the vm_size value is as expected.
	ASSERT_EQ(evt->get_param_by_name("vm_size")->as<uint32_t>(), vm_size);
	// Check that the vm_rss value is as expected.
	ASSERT_EQ(evt->get_param_by_name("vm_rss")->as<uint32_t>(), vm_rss);
	// Check that the vm_swap value is as expected.
	ASSERT_EQ(evt->get_param_by_name("vm_swap")->as<uint32_t>(), vm_swap);
	// Check that the addr value is as expected.
	ASSERT_EQ(evt->get_param_by_name("addr")->as<uint64_t>(), addr);
	// Check that the length value is as expected.
	ASSERT_EQ(evt->get_param_by_name("length")->as<uint64_t>(), length);
	// Check that the prot value is as expected.
	ASSERT_EQ(evt->get_param_by_name("prot")->as<uint32_t>(), prot);
	// Check that the flags value is as expected.
	ASSERT_EQ(evt->get_param_by_name("flags")->as<uint32_t>(), flags);
	// Check that the fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);
	// Check that the pgoffset value is as expected.
	ASSERT_EQ(evt->get_param_by_name("pgoffset")->as<uint64_t>(), pgoffset);
}
