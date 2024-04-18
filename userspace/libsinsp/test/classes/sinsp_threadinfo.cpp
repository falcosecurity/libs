// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <helpers/threads_helpers.h>

TEST(sinsp_threadinfo, get_main_thread)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We are the main thread so here we don't use the thread group info */
	ASSERT_EQ(tinfo->get_main_thread(), tinfo.get());

	/* Now we change the tid so we are no more a main thread and we use the thread group info
	 * we should obtain a nullptr since tinfo doesn't have any thread group info associated.
	 */
	tinfo->m_tid = 25;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	/* We should still obtain a nullptr since the first tinfo in the thread group info is not a main thread. */
	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	/* We should still obtain a nullptr since we put the main thread as the last element of the list. */
	tinfo->m_tginfo->add_thread_to_group(main_tinfo, false);
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	tinfo->m_tginfo->add_thread_to_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_main_thread(), main_tinfo.get());
}

TEST(sinsp_threadinfo, get_num_threads)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 25;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* Thread info doesn't have an associated thread group info */
	ASSERT_EQ(tinfo->get_num_threads(), 0);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 0);

	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_num_threads(), 1);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	tinfo->m_tginfo->add_thread_to_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	/* 1 thread is the main thread so we should return just 1 */
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	main_tinfo->set_dead();

	/* Please note that here we still have 2 because we have just marked the thread as Dead without decrementing the
	 * alive count */
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 2);
}

TEST_F(sinsp_with_test_input, THRD_INFO_assign_children_to_reaper)
{
	DEFAULT_TREE

	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();
	ASSERT_NE(p3_t1_tinfo, nullptr);

	/* The reaper cannot be the current process */
	EXPECT_THROW(p3_t1_tinfo->assign_children_to_reaper(p3_t1_tinfo), sinsp_exception);

	/* children of p3_t1 are p4_t1 and p4_t2 we can reparent them to p1_t1 for example */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 0, 0);

	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_NE(p1_t1_tinfo, nullptr);
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);

	/* all p3_t1 children should be removed */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);

	/* the new parent should be p1_t1 */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p1_t1_tid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p1_t1_tid, p4_t2_vtid, p4_t2_vpid);

	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);

	/* Another call to the reparenting function should do nothing since p3_t1 has no other children */
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_INFO_assign_children_to_a_nullptr)
{
	DEFAULT_TREE

	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_NE(p2_t1_tinfo, nullptr);
	/* This call should change the parent of all children of p2_t1 to `0` */
	p2_t1_tinfo->assign_children_to_reaper(nullptr);

	ASSERT_THREAD_CHILDREN(p2_t1_tid, 0, 0);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, 0);
}
