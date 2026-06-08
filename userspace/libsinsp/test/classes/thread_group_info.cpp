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

/*=============================== THREAD-GROUP-INFO ===========================*/

TEST(thread_group_info, create_thread_group_info) {
	const sinsp inspector;
	const auto& threadinfo_factory = inspector.get_threadinfo_factory();
	auto tinfo = threadinfo_factory.create_shared();
	tinfo.reset();

	/* This will throw an exception since tinfo is expired */
	EXPECT_THROW(thread_group_info(34, true, tinfo), sinsp_exception);

	tinfo = threadinfo_factory.create_shared();
	tinfo->m_tid = 23;
	tinfo->set_pid(23);

	thread_group_info tginfo(tinfo->get_pid(), true, tinfo);
	EXPECT_EQ(tginfo.get_thread_count(), 1);
	EXPECT_TRUE(tginfo.is_reaper());
	EXPECT_EQ(tginfo.get_tgroup_pid(), 23);
	auto threads = tginfo.get_thread_list();
	ASSERT_EQ(threads.size(), 1);
	ASSERT_EQ(tginfo.get_first_thread().get(), tinfo.get());

	/* There are no threads in the thread group info, the first thread should be nullprt */
	tinfo.reset();
	ASSERT_EQ(tginfo.get_first_thread(), nullptr);

	tginfo.set_reaper(false);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.set_reaper(true);
	EXPECT_TRUE(tginfo.is_reaper());
}

TEST(thread_group_info, populate_thread_group_info) {
	const sinsp inspector;
	const auto& threadinfo_factory = inspector.get_threadinfo_factory();
	const auto tinfo = threadinfo_factory.create_shared();
	tinfo->m_tid = 23;
	tinfo->set_pid(23);

	thread_group_info tginfo(tinfo->get_pid(), false, tinfo);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.increment_thread_count();
	tginfo.increment_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 3);
	tginfo.decrement_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 2);

	const auto tinfo1 = threadinfo_factory.create_shared();
	tginfo.add_thread_to_group(tinfo1, true);
	ASSERT_EQ(tginfo.get_first_thread().get(), tinfo1.get());
	EXPECT_EQ(tginfo.get_thread_count(), 3);

	const auto tinfo2 = threadinfo_factory.create_shared();
	tginfo.add_thread_to_group(tinfo2, false);
	ASSERT_EQ(tginfo.get_first_thread().get(), tinfo1.get());
	ASSERT_EQ(tginfo.get_thread_list().back().lock().get(), tinfo2.get());
	EXPECT_EQ(tginfo.get_thread_count(), 4);
}

TEST(thread_group_info, for_each_thread) {
	const sinsp inspector;
	const auto& threadinfo_factory = inspector.get_threadinfo_factory();

	auto tinfo1 = threadinfo_factory.create_shared();
	tinfo1->m_tid = 100;
	tinfo1->set_pid(100);

	thread_group_info tginfo(tinfo1->get_pid(), false, tinfo1);

	auto tinfo2 = threadinfo_factory.create_shared();
	tinfo2->m_tid = 101;
	tinfo2->set_pid(100);
	tginfo.add_thread_to_group(tinfo2, false);

	auto tinfo3 = threadinfo_factory.create_shared();
	tinfo3->m_tid = 102;
	tinfo3->set_pid(100);
	tginfo.add_thread_to_group(tinfo3, false);

	/* Iterate all threads and collect TIDs */
	std::vector<int64_t> tids;
	bool completed = tginfo.for_each_thread([&tids](const std::shared_ptr<sinsp_threadinfo>& t) {
		tids.push_back(t->m_tid);
		return true;
	});
	ASSERT_TRUE(completed);
	ASSERT_EQ(tids.size(), 3);
	EXPECT_EQ(tids[0], 100);
	EXPECT_EQ(tids[1], 101);
	EXPECT_EQ(tids[2], 102);

	/* Early exit: stop after first element */
	tids.clear();
	completed = tginfo.for_each_thread([&tids](const std::shared_ptr<sinsp_threadinfo>& t) {
		tids.push_back(t->m_tid);
		return false;
	});
	ASSERT_FALSE(completed);
	ASSERT_EQ(tids.size(), 1);
	EXPECT_EQ(tids[0], 100);

	/* Expired threads are skipped */
	tinfo2.reset();
	tids.clear();
	tginfo.for_each_thread([&tids](const std::shared_ptr<sinsp_threadinfo>& t) {
		tids.push_back(t->m_tid);
		return true;
	});
	ASSERT_EQ(tids.size(), 2);
	EXPECT_EQ(tids[0], 100);
	EXPECT_EQ(tids[1], 102);
}

TEST(thread_group_info, find_thread) {
	const sinsp inspector;
	const auto& threadinfo_factory = inspector.get_threadinfo_factory();

	auto tinfo1 = threadinfo_factory.create_shared();
	tinfo1->m_tid = 200;
	tinfo1->set_pid(200);

	thread_group_info tginfo(tinfo1->get_pid(), false, tinfo1);

	auto tinfo2 = threadinfo_factory.create_shared();
	tinfo2->m_tid = 201;
	tinfo2->set_pid(200);
	tginfo.add_thread_to_group(tinfo2, false);

	auto tinfo3 = threadinfo_factory.create_shared();
	tinfo3->m_tid = 202;
	tinfo3->set_pid(200);
	tginfo.add_thread_to_group(tinfo3, false);

	/* Find by TID */
	auto result = tginfo.find_thread(
	        [](const std::shared_ptr<sinsp_threadinfo>& t) { return t->m_tid == 201; });
	ASSERT_NE(result, nullptr);
	EXPECT_EQ(result->m_tid, 201);

	/* Find with exclusion (like find_new_reaper) */
	result = tginfo.find_thread([&tinfo1](const std::shared_ptr<sinsp_threadinfo>& t) {
		return t.get() != tinfo1.get();
	});
	ASSERT_NE(result, nullptr);
	EXPECT_EQ(result->m_tid, 201);

	/* No match returns nullptr */
	result = tginfo.find_thread(
	        [](const std::shared_ptr<sinsp_threadinfo>& t) { return t->m_tid == 999; });
	ASSERT_EQ(result, nullptr);

	/* Expired threads are skipped */
	tinfo2.reset();
	result = tginfo.find_thread(
	        [](const std::shared_ptr<sinsp_threadinfo>& t) { return t->m_tid == 201; });
	ASSERT_EQ(result, nullptr);
}
