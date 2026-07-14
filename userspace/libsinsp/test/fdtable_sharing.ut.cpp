// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

// Tests for fd-table contents sharing: the clone parser shares the parent's
// table with the child, and the first modification through either table
// detaches a private copy (copy-on-write).
class fdtable_sharing : public sinsp_with_test_input {
protected:
	// Creates a child process and returns its threadinfo. The clone parser
	// shares the parent's fd-table contents with the child (copy-on-write).
	sinsp_threadinfo* spawn_child(int64_t tid, int64_t parent_tid = INIT_TID) {
		generate_clone_x_event(0, tid, tid, parent_tid);
		auto child = m_inspector.m_thread_manager->find_thread(tid, true).get();
		EXPECT_NE(child, nullptr);
		return child;
	}

	static constexpr int64_t s_fd = sinsp_test_input::open_params::default_fd;
};

TEST_F(fdtable_sharing, untouched_tables_reference_the_shared_empty_contents) {
	add_default_init_thread();
	open_inspector();

	// Secondary threads never own fds (they use their leader's table), so
	// their own tables keep referencing the shared empty contents.
	generate_clone_x_event(0, 21, INIT_PID, INIT_PTID, PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES);
	generate_clone_x_event(0, 22, INIT_PID, INIT_PTID, PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES);
	auto* t1 = m_inspector.m_thread_manager->find_thread(21, true).get();
	auto* t2 = m_inspector.m_thread_manager->find_thread(22, true).get();
	ASSERT_NE(t1, nullptr);
	ASSERT_NE(t2, nullptr);
	ASSERT_FALSE(t1->is_main_thread());

	auto& tt1 = t1->get_fdtable();
	auto& tt2 = t2->get_fdtable();
	ASSERT_EQ(tt1.size(), 0);
	ASSERT_TRUE(tt1.is_shared());
	// Same contents object for every untouched table: no per-table map.
	ASSERT_EQ(tt1.contents_id(), tt2.contents_id());

	// The leader's table, which does own an fd, has private contents.
	auto* leader = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_NE(leader->get_fdtable().contents_id(), tt1.contents_id());
}

TEST_F(fdtable_sharing, fork_shares_the_parent_table) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto& pt = parent->get_fdtable();
	ASSERT_FALSE(pt.is_shared());

	auto* child = spawn_child(20);
	auto& ct = child->get_fdtable();

	ASSERT_TRUE(pt.is_shared());
	ASSERT_TRUE(ct.is_shared());
	ASSERT_EQ(ct.size(), pt.size());
	// Same contents means the same entry objects.
	ASSERT_EQ(ct.find(s_fd), pt.find(s_fd));
	ASSERT_EQ(pt.find(s_fd)->m_name, sinsp_test_input::open_params::default_path);
}

TEST_F(fdtable_sharing, writable_lookup_detaches) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	sinsp_fdinfo* w = ct.find_mut(s_fd);
	ASSERT_NE(w, nullptr);
	w->m_name = "/changed";

	// The write detached the child's copy; the parent is untouched.
	ASSERT_FALSE(pt.is_shared());
	ASSERT_FALSE(ct.is_shared());
	ASSERT_NE(ct.find(s_fd), pt.find(s_fd));
	ASSERT_EQ(ct.find(s_fd)->m_name, "/changed");
	ASSERT_EQ(pt.find(s_fd)->m_name, sinsp_test_input::open_params::default_path);
}

TEST_F(fdtable_sharing, const_lookup_does_not_detach) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	ASSERT_NE(ct.find(s_fd), nullptr);
	ASSERT_NE(pt.find(s_fd), nullptr);
	ASSERT_TRUE(ct.is_shared());
	ASSERT_TRUE(pt.is_shared());
}

TEST_F(fdtable_sharing, add_detaches) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	auto fdi = m_inspector.get_fdinfo_factory().create();
	fdi->m_type = SCAP_FD_FILE_V2;
	fdi->m_name = "/child-only";
	ASSERT_NE(ct.add(100, std::move(fdi)), nullptr);

	ASSERT_FALSE(ct.is_shared());
	ASSERT_NE(ct.find(100), nullptr);
	ASSERT_EQ(pt.find(100), nullptr);
	ASSERT_NE(pt.find(s_fd), nullptr);
}

TEST_F(fdtable_sharing, erase_detaches) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	ASSERT_TRUE(ct.erase(s_fd));

	ASSERT_EQ(ct.find(s_fd), nullptr);
	ASSERT_NE(pt.find(s_fd), nullptr);
	ASSERT_FALSE(pt.is_shared());
}

TEST_F(fdtable_sharing, retain_builds_private_copy_from_survivors) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();
	sinsp_test_input::open_params second_open;
	second_open.fd = 5;
	second_open.path = "/second";
	generate_open_x_event(second_open);

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	ct.retain([](int64_t fd, const sinsp_fdinfo&) { return fd == 5; });

	ASSERT_FALSE(ct.is_shared());
	ASSERT_EQ(ct.size(), 1);
	ASSERT_EQ(ct.find(s_fd), nullptr);
	ASSERT_NE(ct.find(5), nullptr);
	// Parent keeps everything.
	ASSERT_NE(pt.find(s_fd), nullptr);
	ASSERT_NE(pt.find(5), nullptr);
}

TEST_F(fdtable_sharing, clear_leaves_other_sharers_intact) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* child = spawn_child(20);
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	ct.clear();

	ASSERT_EQ(ct.size(), 0);
	ASSERT_NE(pt.find(s_fd), nullptr);
	ASSERT_FALSE(pt.is_shared());
}

TEST_F(fdtable_sharing, chains_detach_independently) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* grandparent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto* parent = spawn_child(20);
	auto* child = spawn_child(30, 20);

	auto& gt = grandparent->get_fdtable();
	auto& pt = parent->get_fdtable();
	auto& ct = child->get_fdtable();

	// G -> P -> C all share one map, inherited fork by fork.
	ASSERT_TRUE(gt.is_shared());
	ASSERT_TRUE(pt.is_shared());
	ASSERT_TRUE(ct.is_shared());

	// The middle of the chain detaching leaves the other two still sharing.
	ASSERT_NE(pt.find_mut(s_fd), nullptr);
	ASSERT_FALSE(pt.is_shared());
	ASSERT_TRUE(gt.is_shared());
	ASSERT_TRUE(ct.is_shared());
	ASSERT_EQ(gt.find(s_fd), ct.find(s_fd));
	ASSERT_NE(gt.find(s_fd), pt.find(s_fd));

	// The last write unshares everything.
	ASSERT_NE(ct.find_mut(s_fd), nullptr);
	ASSERT_FALSE(gt.is_shared());
	ASSERT_FALSE(ct.is_shared());
}

TEST_F(fdtable_sharing, execve_purges_cloexec_without_touching_the_parent) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();
	sinsp_test_input::open_params cloexec_open;
	cloexec_open.fd = 5;
	cloexec_open.path = "/cloexec";
	cloexec_open.flags = PPM_O_CLOEXEC;
	generate_open_x_event(cloexec_open);

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto& pt = parent->get_fdtable();
	spawn_child(20);
	generate_execve_enter_and_exit_event(0, 20, 20, 20, INIT_TID);

	auto* child = m_inspector.m_thread_manager->find_thread(20, true).get();
	auto& ct = child->get_fdtable();

	// The purge kept only the non-CLOEXEC entry, without copying the rest.
	ASSERT_FALSE(ct.is_shared());
	ASSERT_NE(ct.find(s_fd), nullptr);
	ASSERT_EQ(ct.find(5), nullptr);
	// The parent still owns both.
	ASSERT_FALSE(pt.is_shared());
	ASSERT_NE(pt.find(s_fd), nullptr);
	ASSERT_NE(pt.find(5), nullptr);
}

TEST_F(fdtable_sharing, lookup_cache_survives_share_and_detach) {
	add_default_init_thread();
	open_inspector();
	generate_open_x_event();

	auto* parent = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	auto& pt = parent->get_fdtable();

	// Warm the parent's cache, then fork and detach through the child.
	ASSERT_NE(pt.find(s_fd), nullptr);
	auto* child = spawn_child(20);
	auto& ct = child->get_fdtable();
	ASSERT_NE(ct.find(s_fd), nullptr);  // warms the child's cache on the shared map
	sinsp_fdinfo* w = ct.find_mut(s_fd);
	w->m_name = "/changed";

	// Both caches resolve to their own table's current entry.
	ASSERT_EQ(pt.find(s_fd)->m_name, sinsp_test_input::open_params::default_path);
	ASSERT_EQ(ct.find(s_fd)->m_name, "/changed");
}
