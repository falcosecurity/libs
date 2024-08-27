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

/* These are a sort of e2e for the sinsp state, they assert some flows in sinsp */

TEST_F(sinsp_with_test_input, THRD_TABLE_check_default_tree)
{
	/* This test allow us to trust the DEFAULT TREE in other tests */

	/* Instantiate the default tree */
	DEFAULT_TREE

	/* Check Thread info */
	ASSERT_THREAD_INFO_PIDS(INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t3_tid, p2_t3_pid, p2_t3_ptid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p4_t1_ptid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p4_t2_ptid, p4_t2_vtid, p4_t2_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p5_t1_tid, p5_t1_pid, p5_t1_ptid, p5_t1_vtid, p5_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p5_t2_tid, p5_t2_pid, p5_t2_ptid, p5_t2_vtid, p5_t2_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p6_t1_tid, p6_t1_pid, p6_t1_ptid, p6_t1_vtid, p6_t1_vpid);

	/* Check Thread group info */
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 1, true, 1, 1, INIT_TID);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t2_pid, 2, true, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 2, false, 2, 2, p5_t1_tid, p5_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p6_t1_pid, 1, false, 1, 1, p6_t1_tid);

	/* Check children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5, p1_t1_tid, p1_t2_tid, p2_t1_tid, p2_t2_tid, p2_t3_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p4_t2_tid, 2, 2, p5_t1_tid, p5_t2_tid);
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_missing_init_in_proc)
{
	int64_t p1_t1_tid = 2;
	int64_t p1_t1_pid = 2;
	int64_t p1_t1_ptid = INIT_TID;
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* we will call `create_thread_dependencies` but `p1_t1_ptid` doesn't exist so
	 * we will set ptid=0.
	 */
	open_inspector();

	/* Check the fake init thread info just created */
	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_ptid, 0);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_check_init_process_creation)
{
	/* Right now we have only the init process here */
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_TRUE(tinfo->is_main_thread());
	ASSERT_EQ(tinfo->get_main_thread(), tinfo);
	ASSERT_EQ(tinfo->get_parent_thread(), nullptr);
	ASSERT_EQ(tinfo->m_tid, INIT_TID);
	ASSERT_EQ(tinfo->m_pid, INIT_PID);
	ASSERT_EQ(tinfo->m_ptid, INIT_PTID);

	/* assert thread group info */
	ASSERT_TRUE(tinfo->m_tginfo);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);
	ASSERT_EQ(tinfo->m_tginfo->is_reaper(), true);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_list().front().lock().get(), tinfo);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_create_thread_dependencies_after_proc_scan)
{
	/* - init
	 *  - p1_t1
	 *   - p2_t1
	 *  - p1_t2
	 *  - p1_t3 (invalid)
	 *   - p3_t1
	 * - init_t2
	 * - init_t3
	 */

	add_default_init_thread();

	/* p1_t1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* p2_t1 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = 24;

	/* p1_t2 */
	int64_t p1_t2_tid = 25;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID;

	/* p1_t3, this is invalid */
	int64_t p1_t3_tid = 26;
	int64_t p1_t3_pid = -1;
	int64_t p1_t3_ptid = -1;

	/* p3_t1, this is a child of the invalid one */
	int64_t p3_t1_tid = 40;
	int64_t p3_t1_pid = 40;
	int64_t p3_t1_ptid = 26; /* this parent doesn't exist we will reparent it to init */

	/* init_t2, this is a thread of init */
	int64_t init_t2_tid = 2;
	int64_t init_t2_pid = INIT_PID;
	int64_t init_t2_ptid = INIT_PTID;

	/* init_t3, this is a thread of init */
	int64_t init_t3_tid = 3;
	int64_t init_t3_pid = INIT_PID;
	int64_t init_t3_ptid = INIT_PTID;

	/* Populate thread table */
	add_simple_thread(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	add_simple_thread(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	add_simple_thread(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	add_simple_thread(p1_t3_tid, p1_t3_pid, p1_t3_ptid);
	add_simple_thread(init_t2_tid, init_t2_pid, init_t2_ptid);
	add_simple_thread(init_t3_tid, init_t3_pid, init_t3_ptid);

	/* Here we fill the thread table */
	open_inspector();
	ASSERT_EQ(8, m_inspector.m_thread_manager->get_thread_count());

	/* Children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t3_tid, 0, 0);

	/* Thread group */
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 3, true, 3, 3, INIT_TID, init_t2_tid, init_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid)

	auto p1_t3_tinfo = m_inspector.get_thread_ref(p1_t3_tid, false).get();
	ASSERT_TRUE(p1_t3_tinfo);
	ASSERT_FALSE(p1_t3_tinfo->m_tginfo);
	ASSERT_EQ(p1_t3_tinfo->m_ptid, -1);

	/* These shouldn't be init children their parent should be `0` */
	ASSERT_THREAD_INFO_PIDS(init_t2_tid, init_t2_pid, init_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(init_t3_tid, init_t3_pid, init_t3_ptid);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_inactive_threads)
{
	DEFAULT_TREE

	set_threadinfo_last_access_time(INIT_TID, 70);
	set_threadinfo_last_access_time(p1_t1_tid, 70);
	set_threadinfo_last_access_time(p1_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t1_tid, 70);
	set_threadinfo_last_access_time(p3_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t2_tid, 70);
	set_threadinfo_last_access_time(p5_t1_tid, 70);
	set_threadinfo_last_access_time(p5_t2_tid, 70);
	set_threadinfo_last_access_time(p6_t1_tid, 70);
	set_threadinfo_last_access_time(p2_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t3_tid, 70);

	/* This should remove no one */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS, m_inspector.m_thread_manager->get_thread_count());

	/* mark p2_t1 and p2_t3 to remove */
	set_threadinfo_last_access_time(p2_t1_tid, 20);
	set_threadinfo_last_access_time(p2_t3_tid, 20);

	/* p2_t1 shouldn't be removed from the table since it is a leader thread and we still have some threads in that
	 * group while p2_t3 should be removed.
	 */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 2, 2, p2_t1_tid, p2_t2_tid);

	/* Calling PRCTL on an unknown thread should generate an invalid thread */
	int64_t unknown_tid = 61103;
	add_event_advance_ts(increasing_ts(), unknown_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	auto unknown_tinfo = m_inspector.get_thread_ref(unknown_tid, false).get();
	ASSERT_TRUE(unknown_tinfo);
	ASSERT_FALSE(unknown_tinfo->m_tginfo);
	ASSERT_EQ(unknown_tinfo->m_ptid, -1);

	/* This call should remove only invalid threads */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());

	/* successive remove call on `p2_t1` do nothing since it is a main thread */
	m_inspector.remove_thread(p2_t1_tid);
	m_inspector.remove_thread(p2_t1_tid);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());
}

TEST_F(sinsp_with_test_input, THRD_TABLE_traverse_default_tree)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	std::vector<int64_t> traverse_parents;
	sinsp_threadinfo::visitor_func_t visitor = [&traverse_parents](sinsp_threadinfo* pt)
	{
		/* we stop when we reach the init parent */
		traverse_parents.push_back(pt->m_tid);
		if(pt->m_tid == INIT_TID)
		{
			return false;
		}
		return true;
	};

	/*=============================== p4_t1 traverse ===========================*/

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p4_traverse_parents = {p4_t1_ptid, p3_t1_ptid, p2_t1_ptid};

	traverse_parents.clear();
	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p4_traverse_parents);

	/*=============================== p4_t1 traverse ===========================*/

	/*=============================== p5_t2 traverse ===========================*/

	tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p5_traverse_parents = {p5_t2_ptid, p4_t2_ptid, p3_t1_ptid, p2_t1_ptid};

	traverse_parents.clear();
	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p5_traverse_parents);

	/*=============================== p5_t2 traverse ===========================*/

	/*=============================== remove threads ===========================*/

	/* Remove p4_t2 */
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 0, 0)
	/* the reaper is the other thread in the group */
	remove_thread(p4_t2_tid, p4_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t1_pid, 1, true, 2, 1, p4_t1_tid)
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 2, 2, p5_t1_tid, p5_t2_tid)

	/* Remove p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 0, 0)
	remove_thread(p5_t2_tid, p5_t1_tid);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid)

	/* Remove p5_t1 */
	remove_thread(p5_t1_tid, p4_t1_tid);

	/* Now p6_t1 should be assigned to p4_t1 since it is the reaper */
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 3, 1, p6_t1_tid)

	/* Set p2_t1 group as reaper, emulate prctl */
	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid).get();
	tginfo->set_reaper(true);

	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid)

	/* Remove p2_t1 */
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 0, 0)
	remove_thread(p2_t1_tid, p2_t2_tid);
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 1, 1, p3_t1_tid)

	/* Remove p2_t2 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 0, 0)
	remove_thread(p2_t2_tid, p2_t3_tid);
	/* Please note that the parent of `p2_t2` is `init` since it was created with
	 * CLONE_PARENT flag.
	 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 1, 1, p3_t1_tid)

	/* Remove p3_t1 */
	remove_thread(p3_t1_tid, p2_t3_tid);
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 2, 1, p4_t1_tid)

	/*=============================== remove threads ===========================*/

	/*=============================== p6_t1 traverse ===========================*/

	tinfo = m_inspector.get_thread_ref(p6_t1_tid, false).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p6_traverse_parents = {p4_t1_tid, p2_t3_tid, INIT_TID};

	traverse_parents.clear();
	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p6_traverse_parents);

	/*=============================== p6_t1 traverse ===========================*/
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_thread_group_main_thread_first)
{
	DEFAULT_TREE

	/* We remove the main thread, but it is only marked as dead */
	remove_thread(p5_t1_tid, 0);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2, p5_t1_tid, p5_t2_tid)

	/* We remove the secondary thread and we should remove the whole group */
	remove_thread(p5_t2_tid, 0);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p5_t1_pid));
	ASSERT_MISSING_THREAD_INFO(p5_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_thread_group_secondary_thread_first)
{
	DEFAULT_TREE

	/* We remove the secondary thread */
	remove_thread(p5_t2_tid, 0);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 1, p5_t1_tid)

	remove_thread(p5_t1_tid, 0);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p5_t1_pid));
	ASSERT_MISSING_THREAD_INFO(p5_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_TABLE_manage_proc_exit_event_lost)
{
	DEFAULT_TREE

	/* Let's imagine we miss the exit event on p5_t2. At a certain point
	 * we will try to remove it.
	 */
	m_inspector.remove_thread(p5_t2_tid);

	/* Thanks to userspace logic p5_t1 should be the new reaper */
	ASSERT_THREAD_GROUP_INFO(p5_t1_tid, 1, false, 2, 1);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_ignore_not_existent_reaper)
{
	DEFAULT_TREE

	/* not existent reaper, our userspace logic should be able
	 * to assign the right reaper if it doesn't find the one suggested
	 * by the kernel.
	 */
	int64_t unknonw_repaer_tid = 50000;
	remove_thread(p2_t1_tid, unknonw_repaer_tid);

	/* p2_t1 is not expired since it is a main thread and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 3);
	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_TRUE(p2_t1_tinfo);
	ASSERT_EQ(p2_t1_tinfo->m_reaper_tid, p2_t2_tid);

	/* During the process we create also an invalid thread with id `unknonw_repaer_tid` */
	auto unknonw_repaer_tinfo = m_inspector.get_thread_ref(unknonw_repaer_tid, false).get();
	ASSERT_TRUE(unknonw_repaer_tinfo);
	ASSERT_TRUE(unknonw_repaer_tinfo->is_invalid());
}

TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_in_the_default_tree)
{
	DEFAULT_TREE

	/* p5_t1 has no children, when p5_t2 dies p5_t1 receives p6_t1 as child */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 0, 0);
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);
	remove_thread(p5_t2_tid, p5_t1_tid);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true);

	remove_thread(p4_t2_tid, p4_t1_tid);
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 1, 1, p5_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p4_t2_tid, true);

	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, 3);
	/* The kernel says that p2_t1 is a new reaper */
	remove_thread(p4_t1_tid, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 2, 2, p5_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p4_t1_tid, true);

	/* the reaper flag should be set */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, 3);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_max_table_size)
{
	m_inspector.m_thread_manager->set_max_thread_table_size(10000);

	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* Here we want to check that creating a number of threads grater
	 * than m_max_thread_table_size doesn't cause a crash.
	 */
	for(uint32_t i = 1; i < (m_inspector.m_thread_manager->get_max_thread_table_size() + 1000); i++)
	{
		/* we change only the tid */
		generate_clone_x_event(0, pid + i, pid, INIT_TID, PPM_CL_CLONE_THREAD);
	}

	/* We cannot create more than `m_max_thread_table_size`.
	 * We already have `init` so the final size of the group will be
	 * `m_max_thread_table_size -1`
	 */
	int64_t thread_group_size = m_inspector.m_thread_manager->get_max_thread_table_size() - 1;
	ASSERT_THREAD_GROUP_INFO(pid, thread_group_size, false, thread_group_size, thread_group_size);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_many_threads_in_a_group)
{
	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* put HUGE_THREAD_NUMBER threads into the group */
	for(auto i = 1; i < HUGE_THREAD_NUMBER; i++)
	{
		generate_clone_x_event(0, pid + i, pid, INIT_TID);
	}

	int64_t thread_group_size = HUGE_THREAD_NUMBER;
	ASSERT_THREAD_GROUP_INFO(pid, thread_group_size, false, thread_group_size, thread_group_size);

	/* Only `DEFAULT_DEAD_THREADS_THRESHOLD - 1` removal, we need another one */
	for(auto i = 0; i < (DEFAULT_DEAD_THREADS_THRESHOLD - 1); i++)
	{
		remove_thread(pid + i, 0);
	}

	/* we have DEFAULT_DEAD_THREADS_THRESHOLD-1 dead threads so we don't try to clean the expired ones */
	int64_t alive_threads = thread_group_size - (DEFAULT_DEAD_THREADS_THRESHOLD - 1);
	/* Please note that the main thread is not expired so `alive_threads+1` */
	ASSERT_THREAD_GROUP_INFO(20, alive_threads, false, thread_group_size, alive_threads + 1);

	/* remove a random thread and we should clean up the expired ones */
	remove_thread(145, 0);
	alive_threads--;

	/* When we call the decrement logic thread 145 is not dead */
	thread_group_size = alive_threads + 2;
	ASSERT_THREAD_GROUP_INFO(20, alive_threads, false, thread_group_size, alive_threads + 1);

	/* Now if we remove another thread the logic shouldn't be called. */
	remove_thread(146, 0);
	alive_threads--;

	/* thread_group_size doesn't change */
	ASSERT_THREAD_GROUP_INFO(20, alive_threads, false, thread_group_size, alive_threads + 1);

	/* remove all threads in the group */
	for(int i = 0; i <= HUGE_THREAD_NUMBER; i++)
	{
		remove_thread(pid + i, 0);
	}

	/* The thread group info should be removed */
	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(20));
	/* We should have only init */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_add_and_remove_many_threads_in_a_group)
{
	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* put HUGE_THREAD_NUMBER threads into the group and remove them immediately after */
	for(auto i = 1; i < HUGE_THREAD_NUMBER; i++)
	{
		generate_clone_x_event(0, pid + i, pid, INIT_TID);
		remove_thread(pid + i, 0);
	}

	/* How many times the logic will be called.
	 * The first time it is called is after `DEFAULT_DEAD_THREADS_THRESHOLD` dead threads.
	 * When it is called one thread of the dead ones is still not expired so all the next time
	 * the logic will be called after `DEFAULT_DEAD_THREADS_THRESHOLD-1` decrement.
	 * (HUGE_THREAD_NUMBER - DEFAULT_DEAD_THREADS_THRESHOLD -1) here we exclude:
	 * - `-1` the main thread since it never dies
	 * - `-DEFAULT_DEAD_THREADS_THRESHOLD` is the first time we call the logic. To compensate
	 *    this we will do `called_logic++` at the end.
	 */
	int called_logic =
		(HUGE_THREAD_NUMBER - DEFAULT_DEAD_THREADS_THRESHOLD - 1) / (DEFAULT_DEAD_THREADS_THRESHOLD - 1);
	called_logic++;
	int remaining_threads = HUGE_THREAD_NUMBER - (called_logic * (DEFAULT_DEAD_THREADS_THRESHOLD - 1));

	/* we should have only the main thread alive */
	ASSERT_THREAD_GROUP_INFO(20, 1, false, remaining_threads, 1);

	/* main thread + init */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 2);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_many_children)
{
	add_default_init_thread();
	open_inspector();

	int64_t tid = 20;
	for(auto i = 0; i < HUGE_THREAD_NUMBER; i++)
	{
		generate_clone_x_event(0, tid + i, tid + i, INIT_TID);
	}

	ASSERT_THREAD_CHILDREN(INIT_TID, HUGE_THREAD_NUMBER, HUGE_THREAD_NUMBER);

	/* Only `DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1` removal, we need another one */
	for(auto i = 0; i < (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1); i++)
	{
		remove_thread(tid + i, 0);
	}

	int64_t alive_children = HUGE_THREAD_NUMBER - (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1);
	ASSERT_THREAD_CHILDREN(INIT_TID, HUGE_THREAD_NUMBER, alive_children);

	/* remove random thread */
	remove_thread(145, 0);
	alive_children--;

	/* When we clean up the current thread is not taken into account
	 * That's the reason why we need the +1
	 */
	ASSERT_THREAD_CHILDREN(INIT_TID, alive_children + 1, alive_children);

	/* Now if we remove another thread the logic shouldn't be called. */
	remove_thread(146, 0);
	alive_children--;
	ASSERT_THREAD_CHILDREN(INIT_TID, alive_children + 2, alive_children);

	/* remove all threads */
	for(int i = 0; i <= HUGE_THREAD_NUMBER; i++)
	{
		remove_thread(tid + i, 0);
	}

	/* How many times the logic will be called.
	 * The first time it is called is after `DEFAULT_EXPIRED_CHILDREN_THRESHOLD` dead threads.
	 * When it is called one thread of the dead ones is still not expired so all the next time
	 * the logic will be called after `DEFAULT_EXPIRED_CHILDREN_THRESHOLD-1` decrement.
	 * (HUGE_THREAD_NUMBER - DEFAULT_EXPIRED_CHILDREN_THRESHOLD) here we exclude:
	 * - `-DEFAULT_EXPIRED_CHILDREN_THRESHOLD` is the first time we call the logic. To compensate
	 *    this we will do `called_logic++` at the end.
	 */
	int called_logic =
		(HUGE_THREAD_NUMBER - DEFAULT_EXPIRED_CHILDREN_THRESHOLD) / (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1);
	called_logic++;
	int remaining_threads = HUGE_THREAD_NUMBER - (called_logic * (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1));

	ASSERT_THREAD_CHILDREN(INIT_TID, remaining_threads, 0);
	/* Only init process */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_add_and_remove_many_children)
{
	add_default_init_thread();
	open_inspector();

	int64_t tid = 20;
	for(auto i = 0; i < HUGE_THREAD_NUMBER; i++)
	{
		generate_clone_x_event(0, tid + i, tid + i, INIT_TID);
		remove_thread(tid + i, 0);
	}

	int called_logic =
		(HUGE_THREAD_NUMBER - DEFAULT_EXPIRED_CHILDREN_THRESHOLD) / (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1);
	called_logic++;
	int remaining_threads = HUGE_THREAD_NUMBER - (called_logic * (DEFAULT_EXPIRED_CHILDREN_THRESHOLD - 1));

	ASSERT_THREAD_CHILDREN(INIT_TID, remaining_threads, 0);
	/* Only init process */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}
