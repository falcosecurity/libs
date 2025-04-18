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

TEST(sinsp_thread_manager, remove_non_existing_thread) {
	sinsp m_inspector;
	const timestamper timestamper{0};
	sinsp_thread_manager manager(m_inspector.get_threadinfo_factory(),
	                             m_inspector.m_observer,
	                             timestamper,
	                             &m_inspector,
	                             m_inspector.get_thread_manager_dyn_fields(),
	                             m_inspector.get_fdtable_dyn_fields());

	int64_t unknown_tid = 100;
	/* it should do nothing, here we are only checking that nothing will crash */
	manager.remove_thread(unknown_tid);
	manager.remove_thread(unknown_tid);
}

TEST(sinsp_thread_manager, thread_group_manager) {
	sinsp m_inspector;
	const timestamper timestamper{0};
	const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();
	sinsp_thread_manager manager(threadinfo_factory,
	                             m_inspector.m_observer,
	                             timestamper,
	                             &m_inspector,
	                             m_inspector.get_thread_manager_dyn_fields(),
	                             m_inspector.get_fdtable_dyn_fields());

	/* We don't have thread group info here */
	ASSERT_FALSE(manager.get_thread_group_info(8).get());

	const auto tinfo = threadinfo_factory.create_shared();
	tinfo->m_pid = 12;
	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	manager.set_thread_group_info(tinfo->m_pid, tginfo);
	ASSERT_TRUE(manager.get_thread_group_info(tinfo->m_pid).get());

	auto new_tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We should replace the old thread group info */
	manager.set_thread_group_info(tinfo->m_pid, new_tginfo);
	ASSERT_NE(manager.get_thread_group_info(tinfo->m_pid).get(), tginfo.get());
	ASSERT_EQ(manager.get_thread_group_info(tinfo->m_pid).get(), new_tginfo.get());
}

TEST(sinsp_thread_manager, create_thread_dependencies_null_pointer) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo.reset();

	/* The thread info is nullptr */
	EXPECT_THROW(m_inspector.m_thread_manager->create_thread_dependencies(tinfo), sinsp_exception);
}

TEST(sinsp_thread_manager, create_thread_dependencies_invalid_tinfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 4;
	tinfo->m_pid = -1;
	tinfo->m_ptid = 1;

	/* The thread info is invalid we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_FALSE(tinfo->m_tginfo);
}

TEST(sinsp_thread_manager, create_thread_dependencies_tginfo_already_there) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 4;
	tinfo->m_pid = 4;
	tinfo->m_ptid = 1;

	auto tginfo = std::make_shared<thread_group_info>(4, false, tinfo);
	tinfo->m_tginfo = tginfo;

	/* The thread info already has a thread group we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);
}

TEST(sinsp_thread_manager, create_thread_dependencies_new_tginfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51000;
	tinfo->m_ptid = 51001; /* we won't find it in the table, so we will default to 0 */
	tinfo->m_vtid = 20;
	tinfo->m_vpid = 1;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, true, 1, 1);

	ASSERT_EQ(tinfo->m_ptid, 0);
}

TEST(sinsp_thread_manager, create_thread_dependencies_use_existing_tginfo) {
	sinsp m_inspector;
	scap_test_input_data data;
	data.event_count = 0;
	data.thread_count = 0;
	m_inspector.open_test_input(&data, SINSP_MODE_TEST);

	const auto& threadinfo_factory = m_inspector.get_threadinfo_factory();
	const auto tinfo = threadinfo_factory.create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = 51004; /* we won't find it in the table, so we will default to 1 */

	{
		auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);
		m_inspector.m_thread_manager->set_thread_group_info(tinfo->m_pid, tginfo);
	}

	const auto other_tinfo = threadinfo_factory.create_shared();
	other_tinfo->m_tid = 51003;
	other_tinfo->m_pid = 51003;
	other_tinfo->m_ptid = 51004;

	m_inspector.m_thread_manager->create_thread_dependencies(other_tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 2, false, 2, 2);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_create_thread_dependencies_valid_parent) {
	DEFAULT_TREE

	/* new thread will be a child of p6_t1 */
	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = p6_t1_tid;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);
	ASSERT_EQ(tinfo->m_ptid, p6_t1_tid);
	ASSERT_THREAD_CHILDREN(p6_t1_tid, 1, 1);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_create_thread_dependencies_invalid_parent) {
	DEFAULT_TREE

	/* new thread will be a child of p6_t1 */
	auto tinfo = m_inspector.get_threadinfo_factory().create_shared();
	tinfo->m_tid = 51000;
	tinfo->m_pid = 51003;
	tinfo->m_ptid = 8000;

	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);
	/* the new parent will be 0 */
	ASSERT_EQ(tinfo->m_ptid, 0);
}

TEST(sinsp_thread_manager, THRD_MANAGER_find_new_reaper_nullptr) {
	sinsp m_inspector;
	const timestamper timestamper{0};
	sinsp_thread_manager manager(m_inspector.get_threadinfo_factory(),
	                             m_inspector.m_observer,
	                             timestamper,
	                             &m_inspector,
	                             m_inspector.get_thread_manager_dyn_fields(),
	                             m_inspector.get_fdtable_dyn_fields());
	EXPECT_THROW(manager.find_new_reaper(nullptr), sinsp_exception);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_reaper_in_the_same_thread_group) {
	DEFAULT_TREE

	/* We mark it as dead otherwise it will be chosen as a new reaper */
	auto p5_t1_tinfo = m_inspector.get_thread_ref(p5_t1_tid, false).get();
	ASSERT_TRUE(p5_t1_tinfo);
	p5_t1_tinfo->set_dead();

	/* Call the find reaper method, the reaper thread should be the unique thread alive in the group
	 */
	auto reaper = m_inspector.m_thread_manager->find_new_reaper(p5_t1_tinfo);
	ASSERT_EQ(reaper->m_tid, p5_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_reaper_in_the_tree) {
	DEFAULT_TREE

	auto p6_t1_tinfo = m_inspector.get_thread_ref(p6_t1_tid, false).get();
	ASSERT_TRUE(p6_t1_tinfo);

	/* Call the find reaper method, the reaper for p6_t1 should be p4_t1  */
	auto reaper = m_inspector.m_thread_manager->find_new_reaper(p6_t1_tinfo);
	ASSERT_EQ(reaper->m_tid, p4_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_MANAGER_find_new_reaper_detect_loop) {
	DEFAULT_TREE

	/* If we detect a loop the new reaper will be nullptr.
	 * We set p2_t1 group as a reaper.
	 */
	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_TRUE(p2_t1_tinfo);
	p2_t1_tinfo->m_tginfo->set_reaper(true);

	/* We explicitly set p3_t1 ptid to p4_t1, so we create a loop */
	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();
	ASSERT_TRUE(p3_t1_tinfo);
	p3_t1_tinfo->m_ptid = p4_t1_tid;

	/* We will call find_new_reaper on p4_t1 but before doing this we need to
	 * remove p4_t2 otherwise we will have a valid thread in the same group as a new reaper
	 */
	remove_thread(p4_t2_tid, p4_t1_tid);

	/* We call find_new_reaper on p4_t1.
	 * The new reaper should be nullptr since we detected a loop.
	 */
	auto p4_t1_tinfo = m_inspector.get_thread_ref(p4_t1_tid, false).get();
	ASSERT_TRUE(p4_t1_tinfo);
	ASSERT_EQ(m_inspector.m_thread_manager->find_new_reaper(p4_t1_tinfo), nullptr);
}
