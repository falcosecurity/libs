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

/*=============================== PROC EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, PROC_EXIT_not_existent_thread)
{
	DEFAULT_TREE

	/* Before this proc exit init had 5 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* we call the proc_exit event on a not existing thread and we
	 * say the reaper is: 1
	 */
	int64_t unknown_tid = 50000;
	auto evt = generate_proc_exit_event(unknown_tid, INIT_TID);

	/* The thread info associated with the event should be null and INIT should have the same number of children */
	ASSERT_FALSE(evt->get_thread_info());
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_no_children)
{
	DEFAULT_TREE

	/* Before this proc exit init had 5 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	auto evt = generate_proc_exit_event(p5_t1_tid, INIT_TID);

	/* INIT should have the same number of children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	/* The reaper of p5_t1_tinfo should be always -1, p5_t1 has no children so we don't set it */
	auto p5_t1_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t1_tinfo);
	ASSERT_EQ(p5_t1_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t1_tid, PPM_CL_CLOSED, true);

	/* p5_t1 should be in `m_tid_to_remove` */
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t1_tid);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_reaper_0)
{
	DEFAULT_TREE

	/* we call the proc_exit with a reaper equal to 0
	 * our userspace logic should be able to assign the right
	 * reaper even if the kernel one is missing.
	 */
	auto evt = generate_proc_exit_event(p5_t2_tid, 0);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, 0);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);

	/* p5_t1 should be in `m_tid_to_remove` */
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t2_tid);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_negative_reaper)
{
	DEFAULT_TREE

	/* we call the proc_exit with a reaper equal to -1
	 * our userspace logic should be able to assign the right
	 * reaper even if the kernel one is missing.
	 */
	auto evt = generate_proc_exit_event(p5_t2_tid, -1);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t2_tid);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_already_dead_thread)
{
	DEFAULT_TREE

	/* This should never happen a run-time but just to check it */

	/* we mark the thread as dead manually and we check that we don't call `decrement_thread_count`
	 * during PROC_EXIT
	 */
	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	p5_t2_tinfo->set_dead();

	/* we call the proc_exit with a reaper equal to -1
	 * our userspace logic should be able to assign the right
	 * reaper even if the kernel one is missing.
	 */
	auto evt = generate_proc_exit_event(p5_t2_tid, -1);

	/* After the PROC_EXIT event we still have the thread and
	 * the thread count is not decremented.
	 */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 2, false, 2, 2);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	p5_t2_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t2_tid);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_positive_reaper)
{
	DEFAULT_TREE

	/* we call the proc_exit with a reaper equal to -1
	 * our userspace logic should be able to assign the right
	 * reaper even if the kernel one is missing.
	 */
	auto evt = generate_proc_exit_event(p5_t2_tid, 8000);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, 8000);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t2_tid);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_old_event_version)
{
	DEFAULT_TREE

	/* This version of proc_exit event doesn't have the reaper info */
	auto evt = add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_E, 0);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = evt->get_thread_info();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);
	ASSERT_EQ(m_inspector.get_tid_to_remove(), p5_t2_tid);
}

/*=============================== PROC EXIT EVENT ===========================*/
