// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

TEST_F(sinsp_with_test_input, parse_brk_updated_prog_break) {
	add_default_init_thread();
	open_inspector();

	// if the program break is updated the res should be equal to `addr`
	uint64_t res = 83983092;
	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_BRK_4_X,
	                                4,
	                                res,
	                                vm_size,
	                                vm_rss,
	                                vm_swap);

	auto init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);
	ASSERT_EQ(init_tinfo->m_vmsize_kb, vm_size);
	ASSERT_EQ(init_tinfo->m_vmrss_kb, vm_rss);
	ASSERT_EQ(init_tinfo->m_vmswap_kb, vm_swap);

	assert_return_value(evt, res);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), std::to_string(vm_size));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_size"), std::to_string(vm_size));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), std::to_string(vm_rss));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_rss"), std::to_string(vm_rss));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"), std::to_string(vm_swap));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_swap"), std::to_string(vm_swap));
}

TEST_F(sinsp_with_test_input, parse_brk_no_update) {
	add_default_init_thread();
	open_inspector();

	// if the program break is different from `addr`.
	uint64_t res = 83983090;
	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_BRK_4_X,
	                                4,
	                                res,
	                                vm_size,
	                                vm_rss,
	                                vm_swap);

	auto init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);
	// We should always update the info
	ASSERT_EQ(init_tinfo->m_vmsize_kb, vm_size);
	ASSERT_EQ(init_tinfo->m_vmrss_kb, vm_rss);
	ASSERT_EQ(init_tinfo->m_vmswap_kb, vm_swap);

	// BRK can update or not update the program break according to the value we provide. Today we
	// don't consider a failure if the program break in not updated, we consider a failure only if
	// the syscall sets an errno.
	assert_return_value(evt, res);
}
