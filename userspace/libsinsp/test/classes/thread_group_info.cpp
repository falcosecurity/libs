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

TEST(thread_group_info, create_thread_group_info)
{
	std::shared_ptr<sinsp_threadinfo> tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo.reset();

	/* This will throw an exception since tinfo is expired */
	EXPECT_THROW(thread_group_info(34, true, tinfo), sinsp_exception);

	tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	thread_group_info tginfo(tinfo->m_pid, true, tinfo);
	EXPECT_EQ(tginfo.get_thread_count(), 1);
	EXPECT_TRUE(tginfo.is_reaper());
	EXPECT_EQ(tginfo.get_tgroup_pid(), 23);
	auto threads = tginfo.get_thread_list();
	ASSERT_EQ(threads.size(), 1);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo.get());

	/* There are no threads in the thread group info, the first thread should be nullprt */
	tinfo.reset();
	ASSERT_EQ(tginfo.get_first_thread(), nullptr);

	tginfo.set_reaper(false);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.set_reaper(true);
	EXPECT_TRUE(tginfo.is_reaper());
}

TEST(thread_group_info, populate_thread_group_info)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	thread_group_info tginfo(tinfo->m_pid, false, tinfo);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.increment_thread_count();
	tginfo.increment_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 3);
	tginfo.decrement_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 2);

	auto tinfo1 = std::make_shared<sinsp_threadinfo>();
	tginfo.add_thread_to_group(tinfo1, true);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo1.get());
	EXPECT_EQ(tginfo.get_thread_count(), 3);

	auto tinfo2 = std::make_shared<sinsp_threadinfo>();
	tginfo.add_thread_to_group(tinfo2, false);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo1.get());
	ASSERT_EQ(tginfo.get_thread_list().back().lock().get(), tinfo2.get());
	EXPECT_EQ(tginfo.get_thread_count(), 4);
}
