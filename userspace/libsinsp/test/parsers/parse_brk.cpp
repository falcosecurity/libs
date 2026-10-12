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
	uint64_t addr = 8;

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_BRK_4_X,
	                                5,
	                                res,
	                                vm_size,
	                                vm_rss,
	                                vm_swap,
	                                addr);

	auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
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

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[4]"), std::to_string(addr));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.addr"), std::to_string(addr));
}

TEST_F(sinsp_with_test_input, parse_brk_no_update) {
	add_default_init_thread();
	open_inspector();

	// if the program break is different from `addr`.
	uint64_t res = 83983090;
	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;
	uint64_t addr = 8;

	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_BRK_4_X,
	                                5,
	                                res,
	                                vm_size,
	                                vm_rss,
	                                vm_swap,
	                                addr);

	auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
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

/* The memory footprint is the process's. A brk from any thread updates it for all threads. */
TEST_F(sinsp_with_test_input, parse_brk_from_a_secondary_thread) {
	add_default_init_thread();
	open_inspector();
	const int64_t thread_tid = 2;
	generate_clone_x_event(thread_tid, INIT_TID, INIT_PID, INIT_PTID, PPM_CL_CLONE_THREAD);

	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;
	add_event_advance_ts(increasing_ts(),
	                     thread_tid,
	                     PPME_SYSCALL_BRK_4_X,
	                     5,
	                     (uint64_t)83983092,
	                     vm_size,
	                     vm_rss,
	                     vm_swap,
	                     (uint64_t)8);

	for(const int64_t tid : {int64_t{INIT_TID}, thread_tid}) {
		auto evt = generate_random_event(tid);
		ASSERT_EQ(get_field_as_string(evt, "proc.vmsize"), std::to_string(vm_size)) << tid;
		ASSERT_EQ(get_field_as_string(evt, "proc.vmrss"), std::to_string(vm_rss)) << tid;
		ASSERT_EQ(get_field_as_string(evt, "proc.vmswap"), std::to_string(vm_swap)) << tid;
	}
	auto evt = generate_random_event(INIT_TID);
	ASSERT_EQ(get_field_as_string(evt, "thread.vmsize"), std::to_string(vm_size));
}

/* A context switch updates the memory footprint that proc.vmsize reads, also for a process whose
 * main thread sinsp does not know
 */
TEST_F(sinsp_with_test_input, context_switch_without_the_main_thread) {
	add_default_init_thread();
	open_inspector();

	auto thread = m_inspector.get_threadinfo_factory().create();
	thread->m_tid = 71;
	thread->m_pid = 70;
	thread->set_ptid(INIT_TID);
	m_inspector.m_thread_manager->add_thread(std::move(thread), true);

	add_event_advance_ts(increasing_ts(),
	                     71,
	                     PPME_SCHEDSWITCH_6_E,
	                     6,
	                     (int64_t)INIT_TID,
	                     (uint64_t)1,
	                     (uint64_t)2,
	                     (uint32_t)301,
	                     (uint32_t)302,
	                     (uint32_t)303);

	auto evt = generate_random_event(71);
	ASSERT_EQ(get_field_as_string(evt, "proc.vmsize"), "301");
	ASSERT_EQ(get_field_as_string(evt, "proc.vmrss"), "302");
	ASSERT_EQ(get_field_as_string(evt, "proc.vmswap"), "303");
}
