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

/* The debug log lines about parent links, from the last capture_parent_link_logs() on. The
 * fixture resets the logger at the end of each test.
 */
static std::vector<std::string> s_parent_link_logs;

static void capture_parent_link_logs() {
	s_parent_link_logs.clear();
	libsinsp_logger()->set_severity(sinsp_logger::SEV_DEBUG);
	libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity) {
		if(str.find("parent link") != std::string::npos) {
			s_parent_link_logs.push_back(std::move(str));
		}
	});
}

static size_t count_parent_link_logs(const char* kind) {
	return std::count_if(
	        s_parent_link_logs.begin(),
	        s_parent_link_logs.end(),
	        [kind](const std::string& line) { return line.find(kind) != std::string::npos; });
}

/* These are a sort of e2e for the sinsp state, they assert some flows in sinsp */

TEST_F(sinsp_with_test_input, THRD_TABLE_check_default_tree) {
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

TEST_F(sinsp_with_test_input, THRD_TABLE_missing_init_in_proc) {
	int64_t p1_t1_tid = 2;
	int64_t p1_t1_pid = 2;
	int64_t p1_t1_ptid = INIT_TID;
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* we will call `create_thread_dependencies` but `p1_t1_ptid` does not exist, so
	 * the thread has no parent link and keeps the ptid.
	 */
	open_inspector();

	/* Check the fake init thread info just created */
	auto p1_t1_tinfo = m_inspector.m_thread_manager->find_thread(p1_t1_tid, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_tginfo->get_parent(), nullptr);
	ASSERT_EQ(p1_t1_tinfo->get_ptid(), p1_t1_ptid);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_check_init_process_creation) {
	/* Right now we have only the init process here */
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_TRUE(tinfo->is_main_thread());
	ASSERT_EQ(tinfo->get_main_thread(), tinfo);
	ASSERT_EQ(m_inspector.m_thread_manager->find_thread(tinfo->get_ptid(), true), nullptr);
	ASSERT_EQ(tinfo->m_tid, INIT_TID);
	ASSERT_EQ(tinfo->m_pid, INIT_PID);
	ASSERT_EQ(tinfo->get_ptid(), INIT_PTID);

	/* assert thread group info */
	ASSERT_TRUE(tinfo->m_tginfo);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);
	ASSERT_EQ(tinfo->m_tginfo->is_reaper(), true);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_list().front().lock().get(), tinfo);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_create_thread_dependencies_after_proc_scan) {
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

	const auto& thread_manager = m_inspector.m_thread_manager;

	ASSERT_EQ(8, thread_manager->get_thread_count());

	/* Children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t3_tid, 0, 0);

	/* Thread group */
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 3, true, 3, 3, INIT_TID, init_t2_tid, init_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid)

	auto p1_t3_tinfo = thread_manager->find_thread(p1_t3_tid, true).get();
	ASSERT_TRUE(p1_t3_tinfo);
	ASSERT_FALSE(p1_t3_tinfo->m_tginfo);
	ASSERT_EQ(p1_t3_tinfo->get_ptid(), -1);

	/* These shouldn't be init children their parent should be `0` */
	ASSERT_THREAD_INFO_PIDS(init_t2_tid, init_t2_pid, init_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(init_t3_tid, init_t3_pid, init_t3_ptid);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_inactive_threads) {
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

	auto& thread_manager = m_inspector.m_thread_manager;

	/* This should remove no one */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS, thread_manager->get_thread_count());

	/* mark p2_t1 and p2_t3 to remove */
	set_threadinfo_last_access_time(p2_t1_tid, 20);
	set_threadinfo_last_access_time(p2_t3_tid, 20);

	/* p2_t1 shouldn't be removed from the table since it is a leader thread and we still have some
	 * threads in that group while p2_t3 should be removed.
	 */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, thread_manager->get_thread_count());
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 2, 2, p2_t1_tid, p2_t2_tid);

	/* Calling PRCTL on an unknown thread should generate an invalid thread */
	int64_t unknown_tid = 61103;
	add_event_advance_ts(increasing_ts(),
	                     unknown_tid,
	                     PPME_SYSCALL_PRCTL_X,
	                     4,
	                     (int64_t)0,
	                     PPM_PR_GET_CHILD_SUBREAPER,
	                     "<NA>",
	                     (int64_t)0);

	auto unknown_tinfo = thread_manager->find_thread(unknown_tid, true).get();
	ASSERT_TRUE(unknown_tinfo);
	ASSERT_FALSE(unknown_tinfo->m_tginfo);
	ASSERT_EQ(unknown_tinfo->get_ptid(), -1);

	/* This call should remove only invalid threads */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, thread_manager->get_thread_count());

	/* successive remove call on `p2_t1` do nothing since it is a main thread */
	thread_manager->remove_thread(p2_t1_tid);
	thread_manager->remove_thread(p2_t1_tid);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, thread_manager->get_thread_count());
}

TEST_F(sinsp_with_test_input, THRD_TABLE_traverse_default_tree) {
	/* Instantiate the default tree */
	DEFAULT_TREE

	std::vector<int64_t> traverse_parents;
	sinsp_thread_manager::visitor_func_t visitor = [&traverse_parents](sinsp_threadinfo* pt) {
		/* we stop when we reach the init parent */
		traverse_parents.push_back(pt->m_tid);
		if(pt->m_tid == INIT_TID) {
			return false;
		}
		return true;
	};

	const auto& thread_manager = m_inspector.m_thread_manager;

	/*=============================== p4_t1 traverse ===========================*/

	sinsp_threadinfo* tinfo = thread_manager->find_thread(p4_t1_tid, true).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p4_traverse_parents = {p4_t1_ptid, p3_t1_ptid, p2_t1_ptid};

	traverse_parents.clear();
	m_inspector.m_thread_manager->traverse_parent_state(*tinfo, visitor);
	ASSERT_EQ(traverse_parents, expected_p4_traverse_parents);

	/*=============================== p4_t1 traverse ===========================*/

	/*=============================== p5_t2 traverse ===========================*/

	tinfo = thread_manager->find_thread(p5_t2_tid, true).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p5_traverse_parents = {p5_t2_ptid,
	                                                     p4_t2_ptid,
	                                                     p3_t1_ptid,
	                                                     p2_t1_ptid};

	traverse_parents.clear();
	m_inspector.m_thread_manager->traverse_parent_state(*tinfo, visitor);
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
	auto tginfo = thread_manager->get_thread_group_info(p2_t1_pid).get();
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

	tinfo = thread_manager->find_thread(p6_t1_tid, true).get();
	ASSERT_TRUE(tinfo);

	std::vector<int64_t> expected_p6_traverse_parents = {p4_t1_tid, p2_t3_tid, INIT_TID};

	traverse_parents.clear();
	m_inspector.m_thread_manager->traverse_parent_state(*tinfo, visitor);
	ASSERT_EQ(traverse_parents, expected_p6_traverse_parents);

	/*=============================== p6_t1 traverse ===========================*/
}

/* The ptid of a thread in a group is read-only, on the thread and through the thread table. */
TEST_F(sinsp_with_test_input, THRD_TABLE_ptid_is_read_only_in_the_process_tree) {
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto p3 = thread_manager->find_thread(p3_t1_tid, true);
	ASSERT_THROW(p3->set_ptid(p4_t1_tid), sinsp_exception);
	ASSERT_EQ(p3->get_ptid(), p3_t1_ptid);

	libsinsp::state::sinsp_table_owner owner;
	const auto& field = thread_manager->get_field("ptid", SS_PLUGIN_ST_INT64);
	ss_plugin_state_data in{};
	in.s64 = p4_t1_tid;
	ASSERT_EQ(thread_manager->write_entry_field(&owner, p3.get(), &field, &in), SS_PLUGIN_FAILURE);
	ASSERT_EQ(p3->get_ptid(), p3_t1_ptid);

	/* A thread that is not in the table yet accepts the write */
	auto entry = thread_manager->new_entry();
	ASSERT_EQ(thread_manager->write_entry_field(&owner, entry.get(), &field, &in),
	          SS_PLUGIN_SUCCESS);
	ASSERT_EQ(static_cast<sinsp_threadinfo*>(entry.get())->get_ptid(), p4_t1_tid);
}

/* A thread without a group has no parent to follow. Two such threads that name each other as
 * parents cannot make a walk loop.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_walk_from_a_thread_out_of_the_tree_ends) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	for(const auto& [tid, ptid] : {std::pair<int64_t, int64_t>{100, 101}, {101, 100}}) {
		auto thread = m_inspector.get_threadinfo_factory().create();
		thread->m_tid = tid;
		thread->m_pid = -1;
		thread->set_ptid(ptid);
		thread_manager->add_thread(std::move(thread), true);
	}

	auto tinfo = thread_manager->find_thread(100, true);
	ASSERT_EQ(tinfo->m_tginfo, nullptr);
	ASSERT_EQ(thread_manager->get_parent_thread(*tinfo), nullptr);
	uint32_t visited = 0;
	sinsp_thread_manager::visitor_func_t visitor = [&visited](sinsp_threadinfo*) {
		return ++visited < 1000;
	};
	thread_manager->traverse_parent_state(*tinfo, visitor);
	ASSERT_EQ(visited, 0);
}

/* relink() refuses a link that goes up in rank, also when the link closes no cycle. Here,
 * the test first moves a off the chain of c, and then puts a under c.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_relink_up_in_rank_is_refused) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t a = 10;
	const int64_t b = 11;
	const int64_t c = 12;
	generate_clone_x_event(0, a, a, INIT_TID);
	generate_clone_x_event(0, b, b, a);
	generate_clone_x_event(0, c, c, b);
	auto a_tinfo = thread_manager->find_thread(a, true);
	auto b_tinfo = thread_manager->find_thread(b, true);
	auto c_tinfo = thread_manager->find_thread(c, true);

	const auto& init_group = thread_manager->get_thread_group_info(INIT_PID);
	ASSERT_TRUE(b_tinfo->m_tginfo->relink(init_group, INIT_TID));
	ASSERT_FALSE(a_tinfo->m_tginfo->relink(c_tinfo->m_tginfo, c));
	ASSERT_EQ(a_tinfo->m_tginfo->get_parent(), init_group);
	ASSERT_TRUE(c_tinfo->m_tginfo->chain_ends());
}

/* The depth is more than any cap, because a process tree has no depth limit. */
static constexpr int64_t s_deep_tree = 300;

TEST_F(sinsp_with_test_input, THRD_TABLE_traverse_deep_chain) {
	add_default_init_thread();
	open_inspector();

	/* init <- 2 <- 3 <- ... <- s_deep_tree + 1 */
	for(int64_t tid = 2; tid <= s_deep_tree + 1; tid++) {
		generate_clone_x_event(0, tid, tid, tid - 1);
	}

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto leaf = thread_manager->find_thread(s_deep_tree + 1, true).get();
	ASSERT_TRUE(leaf);

	int64_t visited = 0;
	int64_t last = -1;
	sinsp_thread_manager::visitor_func_t visitor = [&](sinsp_threadinfo* pt) {
		visited++;
		last = pt->m_tid;
		return true;
	};
	thread_manager->traverse_parent_state(*leaf, visitor);
	ASSERT_EQ(visited, s_deep_tree);
	ASSERT_EQ(last, INIT_TID);

	auto top = thread_manager->get_ancestor_process(*leaf, s_deep_tree);
	ASSERT_TRUE(top);
	ASSERT_EQ(top->m_tid, INIT_TID);
}

/* Every ancestor is a subreaper, and they die from the bottom up. The ancestor above reaps each
 * one. At the end, the leaf is under init.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_through_a_deep_chain_of_reapers) {
	add_default_init_thread();
	open_inspector();
	for(int64_t tid = 2; tid <= s_deep_tree + 1; tid++) {
		generate_clone_x_event(0, tid, tid, tid - 1);
		m_inspector.m_thread_manager->get_thread_group_info(tid)->set_reaper(true);
	}

	for(int64_t tid = s_deep_tree; tid >= 2; tid--) {
		remove_thread(tid, tid - 1);
	}
	ASSERT_THREAD_INFO_PIDS(s_deep_tree + 1, s_deep_tree + 1, INIT_TID);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_through_a_deep_chain_without_kernel_reaper) {
	add_default_init_thread();
	open_inspector();
	for(int64_t tid = 2; tid <= s_deep_tree + 1; tid++) {
		generate_clone_x_event(0, tid, tid, tid - 1);
		m_inspector.m_thread_manager->get_thread_group_info(tid)->set_reaper(true);
	}

	/* -1: the kernel did not give the reaper */
	for(int64_t tid = s_deep_tree; tid >= 2; tid--) {
		remove_thread(tid, -1);
	}
	ASSERT_THREAD_INFO_PIDS(s_deep_tree + 1, s_deep_tree + 1, INIT_TID);
}

/* A loop in the /proc ppids is longer than any cap. sinsp refuses the link that closes it. */
TEST_F(sinsp_with_test_input, THRD_TABLE_proc_scan_long_ppid_loop) {
	capture_parent_link_logs();
	add_default_init_thread();
	for(int64_t i = 0; i < s_deep_tree; i++) {
		add_simple_thread(1000 + i, 1000 + i, 1000 + (i + 1) % s_deep_tree);
	}
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto tinfo = thread_manager->find_thread(1000, true).get();
	ASSERT_TRUE(tinfo);
	uint64_t visited = 0;
	sinsp_thread_manager::visitor_func_t visitor = [&visited](sinsp_threadinfo*) {
		visited++;
		return true;
	};
	thread_manager->traverse_parent_state(*tinfo, visitor);
	ASSERT_LT(visited, s_deep_tree);

	/* sinsp refuses only the link that closes the loop, and keeps its tid */
	int64_t unlinked = 0;
	for(int64_t i = 0; i < s_deep_tree; i++) {
		auto thread = thread_manager->find_thread(1000 + i, true);
		ASSERT_TRUE(thread->m_tginfo->chain_ends());
		if(thread->m_tginfo->get_parent() == nullptr) {
			unlinked++;
			ASSERT_EQ(thread->get_ptid(), 1000 + (i + 1) % s_deep_tree);
		}
	}
	ASSERT_EQ(unlinked, 1);
	ASSERT_EQ(count_parent_link_logs("Refused"), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_thread_group_main_thread_first) {
	DEFAULT_TREE

	/* We remove the main thread, but it is only marked as dead */
	remove_thread(p5_t1_tid, 0);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2, p5_t1_tid, p5_t2_tid)

	/* We remove the secondary thread, and we should remove the whole group */
	remove_thread(p5_t2_tid, 0);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p5_t1_pid));
	ASSERT_MISSING_THREAD_INFO(p5_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_thread_group_secondary_thread_first) {
	DEFAULT_TREE

	/* We remove the secondary thread */
	remove_thread(p5_t2_tid, 0);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 1, p5_t1_tid)

	remove_thread(p5_t1_tid, 0);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p5_t1_pid));
	ASSERT_MISSING_THREAD_INFO(p5_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_TABLE_manage_proc_exit_event_lost) {
	DEFAULT_TREE

	/* Let's imagine we miss the exit event on p5_t2. At a certain point
	 * we will try to remove it.
	 */
	m_inspector.m_thread_manager->remove_thread(p5_t2_tid);

	/* Thanks to userspace logic p5_t1 should be the new reaper */
	ASSERT_THREAD_GROUP_INFO(p5_t1_tid, 1, false, 2, 1);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_ignore_not_existent_reaper) {
	DEFAULT_TREE

	/* not existent reaper, our userspace logic should be able
	 * to assign the right reaper if it doesn't find the one suggested
	 * by the kernel.
	 */
	int64_t unknown_reaper_tid = 50000;
	remove_thread(p2_t1_tid, unknown_reaper_tid);

	const auto& thread_manager = m_inspector.m_thread_manager;

	/* p2_t1 is not expired since it is a main thread and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 3);
	auto p2_t1_tinfo = thread_manager->find_thread(p2_t1_tid, true).get();
	ASSERT_TRUE(p2_t1_tinfo);

	/* While the group lives, its children go to its first live thread. The reaper from the kernel
	 * counts only after the process is gone.
	 */
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p2_t2_tid);
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 1, 1, p3_t1_tid);
	ASSERT_FALSE(thread_manager->find_thread(unknown_reaper_tid, true));
}

TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_in_the_default_tree) {
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

/* If the kernel does not give the reaper, the children of a dead process go to the nearest
 * subreaper above it.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_to_subreaper_without_kernel_reaper) {
	DEFAULT_TREE

	m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid)->set_reaper(true);

	/* -1: the kernel did not give the reaper */
	remove_thread(p3_t1_tid, -1);
	ASSERT_MISSING_THREAD_INFO(p3_t1_tid, true);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p2_t1_tid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p2_t1_tid, p4_t2_vtid, p4_t2_vpid);

	ASSERT_THREAD_CHILDREN(p2_t1_tid, 3, 2, p4_t1_tid, p4_t2_tid);
}

/* If no subreaper is between them, the children go to init. */
TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_to_init_without_kernel_reaper) {
	DEFAULT_TREE

	remove_thread(p3_t1_tid, -1);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, INIT_TID, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, INIT_TID, p4_t2_vtid, p4_t2_vpid);
}

/* The reaper search runs when a child is read, so a subreaper set after the death counts. */
TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_sees_subreaper_set_after_death) {
	DEFAULT_TREE

	remove_thread(p3_t1_tid, -1);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, INIT_TID, p4_t1_vtid, p4_t1_vpid);

	m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid)->set_reaper(true);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p2_t1_tid, p4_t1_vtid, p4_t1_vpid);
}

/* The search stays in the pid namespace of the dead process. p4 is in a container and its
 * parent p3 is not, so the children of p4 get no parent.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_reparenting_stops_at_pid_namespace) {
	DEFAULT_TREE

	remove_thread(p5_t2_tid, -1);
	remove_thread(p5_t1_tid, -1);
	/* p4 is the init of the container (vpid 1), so it is a reaper. Its main thread takes p6. */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p6_t1_tid, p6_t1_pid, p4_t1_tid, p6_t1_vtid, p6_t1_vpid);

	remove_thread(p4_t2_tid, -1);
	remove_thread(p4_t1_tid, -1);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p6_t1_tid, p6_t1_pid, 0, p6_t1_vtid, p6_t1_vpid);
}

/* A daemon detaches with a double fork. The middle process stays as a tombstone while the
 * daemon lives, and sinsp frees it when the daemon exits.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_tombstone_lives_as_long_as_its_children) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	constexpr int64_t daemons = 100;
	const int64_t shell = 10;
	generate_clone_x_event(0, shell, shell, INIT_TID);

	std::vector<std::weak_ptr<thread_group_info>> tombstones;
	for(int64_t i = 0; i < daemons; i++) {
		const int64_t middle = 1000 + 2 * i;
		const int64_t daemon = middle + 1;
		generate_clone_x_event(0, middle, middle, shell);
		generate_clone_x_event(0, daemon, daemon, middle);
		tombstones.push_back(thread_manager->get_thread_group_info(middle));
		/* the kernel names init as the reaper */
		remove_thread(middle, INIT_TID);
	}

	for(int64_t i = 0; i < daemons; i++) {
		const int64_t middle = 1000 + 2 * i;
		ASSERT_MISSING_THREAD_INFO(middle, true);
		ASSERT_FALSE(thread_manager->get_thread_group_info(middle));
		ASSERT_FALSE(tombstones[i].expired());
		ASSERT_THREAD_INFO_PIDS(middle + 1, middle + 1, INIT_TID);
	}
	ASSERT_THREAD_CHILDREN(INIT_TID, daemons + 1, daemons + 1);

	for(int64_t i = 0; i < daemons; i++) {
		remove_thread(1000 + 2 * i + 1, INIT_TID);
		ASSERT_TRUE(tombstones[i].expired());
	}
}

/* The next clone of the child links it past a dead parent with a known reaper. This frees the
 * tombstone of the parent.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_child_event_skips_reaped_parent) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t middle = 1000;
	const int64_t daemon = 1001;
	generate_clone_x_event(0, middle, middle, INIT_TID);
	generate_clone_x_event(0, daemon, daemon, middle);
	std::weak_ptr<thread_group_info> tombstone = thread_manager->get_thread_group_info(middle);
	remove_thread(middle, INIT_TID);
	ASSERT_FALSE(tombstone.expired());

	/* An ordinary event does not change the link */
	generate_random_event(daemon);
	ASSERT_FALSE(tombstone.expired());

	/* the daemon forks a worker */
	generate_clone_x_event(daemon + 1, daemon, daemon, INIT_TID);
	ASSERT_TRUE(tombstone.expired());
	ASSERT_THREAD_INFO_PIDS(daemon, daemon, INIT_TID);
	auto daemon_tinfo = thread_manager->find_thread(daemon, true);
	ASSERT_EQ(daemon_tinfo->m_tginfo->get_parent(),
	          thread_manager->get_thread_group_info(INIT_PID));
}

/* The next execve of the child does the same. */
TEST_F(sinsp_with_test_input, THRD_TABLE_child_execve_skips_reaped_parent) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t middle = 1000;
	const int64_t daemon = 1001;
	generate_clone_x_event(0, middle, middle, INIT_TID);
	generate_clone_x_event(0, daemon, daemon, middle);
	std::weak_ptr<thread_group_info> tombstone = thread_manager->get_thread_group_info(middle);
	remove_thread(middle, INIT_TID);
	ASSERT_FALSE(tombstone.expired());

	generate_execve_enter_and_exit_event(0, daemon, daemon, daemon, INIT_TID);
	ASSERT_TRUE(tombstone.expired());
	ASSERT_THREAD_INFO_PIDS(daemon, daemon, INIT_TID);
}

/* The same is true for a parent with an unknown reaper. The search runs once, and sinsp links its
 * result.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_child_event_skips_unreaped_parent) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t middle = 1000;
	const int64_t daemon = 1001;
	generate_clone_x_event(0, middle, middle, INIT_TID);
	generate_clone_x_event(0, daemon, daemon, middle);
	std::weak_ptr<thread_group_info> tombstone = thread_manager->get_thread_group_info(middle);
	remove_thread(middle, -1);

	generate_clone_x_event(daemon + 1, daemon, daemon, INIT_TID);
	ASSERT_TRUE(tombstone.expired());
	ASSERT_THREAD_INFO_PIDS(daemon, daemon, INIT_TID);
	ASSERT_EQ(thread_manager->find_thread(daemon, true)->m_tginfo->get_parent(),
	          thread_manager->get_thread_group_info(INIT_PID));
}

/* A process that dies after its parent, with an unknown reaper, links past the dead parent. This
 * frees the parent.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_unreaped_process_dying_after_its_parent_drops_it) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t a = 10;
	const int64_t b = 11;
	const int64_t c = 12;
	generate_clone_x_event(0, a, a, INIT_TID);
	generate_clone_x_event(0, b, b, a);
	generate_clone_x_event(0, c, c, b);
	std::weak_ptr<thread_group_info> a_tombstone = thread_manager->get_thread_group_info(a);
	auto b_group = thread_manager->get_thread_group_info(b);

	/* -1: the kernel did not give the reaper */
	remove_thread(a, -1);
	ASSERT_FALSE(a_tombstone.expired());
	remove_thread(b, -1);
	ASSERT_TRUE(a_tombstone.expired());
	ASSERT_EQ(b_group->get_parent(), thread_manager->get_thread_group_info(INIT_PID));
	ASSERT_FALSE(b_group->is_reaper_known());
	ASSERT_THREAD_INFO_PIDS(c, c, INIT_TID);
}

/* A reaper from the kernel that is below the dying process ranks higher. For example, a tid was
 * reused after a lost exit. The link is refused, and readers search for a reaper.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_reaper_below_the_dying_process_is_refused) {
	capture_parent_link_logs();
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto p3_group = thread_manager->get_thread_group_info(p3_t1_pid);
	remove_thread(p3_t1_tid, p5_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p3_t1_tid, true);

	ASSERT_EQ(count_parent_link_logs("Refused"), 1);
	ASSERT_FALSE(p3_group->is_reaper_known());
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 2, false, 2, 2);
	auto p6 = thread_manager->find_thread(p6_t1_tid, true);
	ASSERT_TRUE(p6->m_tginfo->chain_ends());
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, INIT_TID, p4_t1_vtid, p4_t1_vpid);
}

/* A reaper that is not above the dying process, but ranks lower, is linked. */
TEST_F(sinsp_with_test_input, THRD_TABLE_reaper_off_the_dying_process_chain_is_linked) {
	capture_parent_link_logs();
	DEFAULT_TREE

	remove_thread(p4_t2_tid, p1_t1_tid);
	remove_thread(p4_t1_tid, p1_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p4_t1_tid, true);

	ASSERT_EQ(count_parent_link_logs("Refused"), 0);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, true, 2, 2);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p5_t1_tid, p5_t1_pid, p1_t1_tid, p5_t1_vtid, p5_t1_vpid);
}

/* The usual reaper, above the dying process, is linked. */
TEST_F(sinsp_with_test_input, THRD_TABLE_reaper_above_the_dying_process_is_linked) {
	capture_parent_link_logs();
	DEFAULT_TREE

	remove_thread(p3_t1_tid, INIT_TID);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, INIT_TID, p4_t1_vtid, p4_t1_vpid);
	ASSERT_EQ(count_parent_link_logs("Refused"), 0);
}

/* A process from /proc with a parent that is not in the table keeps the tid of the parent. When
 * the parent appears, the process links to it on its next execve.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_parent_known_later_links_on_execve) {
	capture_parent_link_logs();
	add_default_init_thread();
	const int64_t parent = 50;
	const int64_t child = 60;
	add_simple_thread(child, child, parent);
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto child_tinfo = thread_manager->find_thread(child, true);
	ASSERT_EQ(child_tinfo->m_tginfo->get_parent(), nullptr);
	ASSERT_EQ(child_tinfo->get_ptid(), parent);

	generate_clone_x_event(0, parent, parent, INIT_TID);
	ASSERT_EQ(child_tinfo->m_tginfo->get_parent(), nullptr);

	generate_execve_enter_and_exit_event(0, child, child, child, parent);
	ASSERT_EQ(count_parent_link_logs("Late"), 1);
	ASSERT_EQ(child_tinfo->m_tginfo->get_parent(), thread_manager->get_thread_group_info(parent));
	ASSERT_THREAD_INFO_PIDS(child, child, parent);
	ASSERT_EQ(thread_manager->get_ancestor_process(*child_tinfo, 2)->m_tid, INIT_TID);
}

/* The exception: the parent ranks as high, because its own parent is also unknown. */
TEST_F(sinsp_with_test_input, THRD_TABLE_parent_of_unknown_ancestry_is_not_linked_later) {
	capture_parent_link_logs();
	add_default_init_thread();
	const int64_t parent = 50;
	const int64_t child = 60;
	add_simple_thread(child, child, parent);
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	auto child_tinfo = thread_manager->find_thread(child, true);
	/* the parent of the parent, 40, is not in the table */
	generate_clone_x_event(0, parent, parent, 40);
	ASSERT_EQ(thread_manager->get_thread_group_info(parent)->get_rank(),
	          child_tinfo->m_tginfo->get_rank());

	generate_execve_enter_and_exit_event(0, child, child, child, parent);
	ASSERT_EQ(count_parent_link_logs("Late"), 0);
	ASSERT_EQ(count_parent_link_logs("Refused"), 1);
	ASSERT_EQ(child_tinfo->m_tginfo->get_parent(), nullptr);
	ASSERT_EQ(child_tinfo->get_ptid(), parent);

	/* A refused tid is not tried again */
	generate_execve_enter_and_exit_event(0, child, child, child, parent);
	ASSERT_EQ(count_parent_link_logs("Refused"), 1);
}

#ifdef _DEBUG
/* A shortcut (a direct link past dead parents) walks the chain of its group and then stores the
 * link. A relink can come in between. A relink that puts the target of the shortcut under the
 * group goes up in rank, so it is refused.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_relink_between_a_shortcut_walk_and_its_store) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t a = 10;
	const int64_t b = 11;
	const int64_t c = 12;
	generate_clone_x_event(0, a, a, INIT_TID);
	generate_clone_x_event(0, b, b, a);
	generate_clone_x_event(0, c, c, b);

	auto a_tinfo = thread_manager->find_thread(a, true);
	auto c_tinfo = thread_manager->find_thread(c, true);
	remove_thread(b, a);
	bool ran = false;
	bool relinked = true;
	thread_group_info::s_before_shortcut_store = [&] {
		if(!ran) {
			ran = true;
			/* Put a under c. The chain of c still leads to a, through the dead b */
			relinked = a_tinfo->m_tginfo->relink(c_tinfo->m_tginfo, c);
		}
	};
	generate_clone_x_event(1000, c, c, b);
	thread_group_info::s_before_shortcut_store = nullptr;

	ASSERT_TRUE(ran);
	ASSERT_FALSE(relinked);
	ASSERT_TRUE(a_tinfo->m_tginfo->chain_ends());
	ASSERT_TRUE(c_tinfo->m_tginfo->chain_ends());
	ASSERT_EQ(c_tinfo->m_tginfo->get_parent(), a_tinfo->m_tginfo);
	ASSERT_EQ(a_tinfo->m_tginfo->get_parent(), thread_manager->get_thread_group_info(INIT_PID));
}

/* If the link of the group itself is relinked in between, the relink wins and the shortcut is
 * not stored.
 */
TEST_F(sinsp_with_test_input, THRD_TABLE_shortcut_gives_way_to_a_relink_of_its_own_link) {
	add_default_init_thread();
	open_inspector();

	const auto& thread_manager = m_inspector.m_thread_manager;
	const int64_t a = 10;
	const int64_t b = 11;
	const int64_t c = 12;
	generate_clone_x_event(0, a, a, INIT_TID);
	generate_clone_x_event(0, b, b, a);
	generate_clone_x_event(0, c, c, b);
	remove_thread(b, a);

	auto c_tinfo = thread_manager->find_thread(c, true);
	bool ran = false;
	thread_group_info::s_before_shortcut_store = [&] {
		if(!ran) {
			ran = true;
			c_tinfo->m_tginfo->relink(thread_manager->get_thread_group_info(INIT_PID), INIT_TID);
		}
	};
	generate_clone_x_event(1000, c, c, b);
	thread_group_info::s_before_shortcut_store = nullptr;

	ASSERT_TRUE(ran);
	ASSERT_EQ(c_tinfo->m_tginfo->get_parent(), thread_manager->get_thread_group_info(INIT_PID));
	ASSERT_THREAD_INFO_PIDS(c, c, INIT_TID);
}
#endif

TEST_F(sinsp_with_test_input, THRD_TABLE_max_table_size) {
	const auto& thread_manager = m_inspector.m_thread_manager;
	thread_manager->set_max_thread_table_size(10000);

	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* Here we want to check that creating a number of threads grater
	 * than m_max_thread_table_size doesn't cause a crash.
	 */
	for(uint32_t i = 1; i < (thread_manager->get_max_thread_table_size() + 1000); i++) {
		/* we change only the tid */
		generate_clone_x_event(0, pid + i, pid, INIT_TID, PPM_CL_CLONE_THREAD);
	}

	/* We cannot create more than `m_max_thread_table_size`.
	 * We already have `init` so the final size of the group will be
	 * `m_max_thread_table_size -1`
	 */
	const int64_t thread_group_size = thread_manager->get_max_thread_table_size() - 1;
	ASSERT_THREAD_GROUP_INFO(pid, thread_group_size, false, thread_group_size, thread_group_size);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_many_threads_in_a_group) {
	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* put HUGE_THREAD_NUMBER threads into the group */
	for(auto i = 1; i < HUGE_THREAD_NUMBER; i++) {
		generate_clone_x_event(0, pid + i, pid, INIT_TID);
	}

	int64_t thread_group_size = HUGE_THREAD_NUMBER;
	ASSERT_THREAD_GROUP_INFO(pid, thread_group_size, false, thread_group_size, thread_group_size);

	/* Only `DEFAULT_DEAD_THREADS_THRESHOLD - 1` removal, we need another one */
	for(auto i = 0; i < (DEFAULT_DEAD_THREADS_THRESHOLD - 1); i++) {
		remove_thread(pid + i, 0);
	}

	/* we have DEFAULT_DEAD_THREADS_THRESHOLD-1 dead threads so we don't try to clean the expired
	 * ones */
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
	for(int i = 0; i <= HUGE_THREAD_NUMBER; i++) {
		remove_thread(pid + i, 0);
	}

	const auto& thread_manager = m_inspector.m_thread_manager;

	/* The thread group info should be removed */
	ASSERT_FALSE(thread_manager->get_thread_group_info(20));
	/* We should have only init */
	ASSERT_EQ(thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_add_and_remove_many_threads_in_a_group) {
	add_default_init_thread();
	open_inspector();

	/* generate a new thread group with pid=20 */
	int64_t pid = 20;
	generate_clone_x_event(0, pid, pid, INIT_TID);

	/* put HUGE_THREAD_NUMBER threads into the group and remove them immediately after */
	for(auto i = 1; i < HUGE_THREAD_NUMBER; i++) {
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
	int called_logic = (HUGE_THREAD_NUMBER - DEFAULT_DEAD_THREADS_THRESHOLD - 1) /
	                   (DEFAULT_DEAD_THREADS_THRESHOLD - 1);
	called_logic++;
	int remaining_threads =
	        HUGE_THREAD_NUMBER - (called_logic * (DEFAULT_DEAD_THREADS_THRESHOLD - 1));

	/* we should have only the main thread alive */
	ASSERT_THREAD_GROUP_INFO(20, 1, false, remaining_threads, 1);

	/* main thread + init */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 2);
}

/* A removed child stops being a child at once, for any number of children. */
TEST_F(sinsp_with_test_input, THRD_TABLE_many_children) {
	add_default_init_thread();
	open_inspector();

	int64_t tid = 20;
	for(auto i = 0; i < HUGE_THREAD_NUMBER; i++) {
		generate_clone_x_event(0, tid + i, tid + i, INIT_TID);
	}

	ASSERT_THREAD_CHILDREN(INIT_TID, HUGE_THREAD_NUMBER, HUGE_THREAD_NUMBER);

	constexpr int removed = 9;
	for(auto i = 0; i < removed; i++) {
		remove_thread(tid + i, 0);
	}

	int64_t alive_children = HUGE_THREAD_NUMBER - removed;
	ASSERT_THREAD_CHILDREN(INIT_TID, alive_children, alive_children);

	/* remove random thread */
	remove_thread(145, 0);
	alive_children--;
	ASSERT_THREAD_CHILDREN(INIT_TID, alive_children, alive_children);

	remove_thread(146, 0);
	alive_children--;
	ASSERT_THREAD_CHILDREN(INIT_TID, alive_children, alive_children);

	/* remove all threads */
	for(int i = 0; i <= HUGE_THREAD_NUMBER; i++) {
		remove_thread(tid + i, 0);
	}

	ASSERT_THREAD_CHILDREN(INIT_TID, 0, 0);
	/* Only init process */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_add_and_remove_many_children) {
	add_default_init_thread();
	open_inspector();

	int64_t tid = 20;
	for(auto i = 0; i < HUGE_THREAD_NUMBER; i++) {
		generate_clone_x_event(0, tid + i, tid + i, INIT_TID);
		remove_thread(tid + i, 0);
	}

	ASSERT_THREAD_CHILDREN(INIT_TID, 0, 0);
	/* Only init process */
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 1);
}

TEST_F(sinsp_with_test_input, THRD_TABLE_proc_apid_ppid) {
	DEFAULT_TREE

	const auto& thread_manager = m_inspector.m_thread_manager;

	// Thread p5_t1_ptid is generated by p4_t2_tid, which is a thread
	// Retrieve it to check apid and ppid
	auto p5_t1_info = thread_manager->find_thread(p5_t1_tid, true).get();
	ASSERT_EQ(p5_t1_info->get_ptid(), p4_t2_tid);

	auto p4_t1_info = thread_manager->find_thread(p4_t1_tid, true).get();
	auto p5_t1_parent_info = m_inspector.m_thread_manager->get_ancestor_process(*p5_t1_info);
	ASSERT_EQ(p4_t1_info->m_pid, p5_t1_parent_info->m_pid);

	auto p3_t1_info = thread_manager->find_thread(p3_t1_tid, true).get();
	auto p5_t1_gparent_info = m_inspector.m_thread_manager->get_ancestor_process(*p5_t1_info, 2);
	ASSERT_EQ(p3_t1_info->m_pid, p5_t1_gparent_info->m_pid);
}
