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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, PROC_FILTER_nthreds)
{
	DEFAULT_TREE

	/* we call a random event to obtain an event associated with this thread info */
	auto evt = generate_random_event(p2_t1_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "3");

	/* we call proc_exit so we should decrement the count by 1 */
	evt = generate_proc_exit_event(p2_t1_tid, p2_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "2");

	/* we remove the thread group info from the thread so we should obtain a count equal to 0 */
	auto p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_TRUE(p2_t2_tinfo);
	p2_t2_tinfo->m_tginfo.reset();

	evt = generate_random_event(p2_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "0");
}

TEST_F(sinsp_with_test_input, PROC_FILTER_nchilds)
{
	DEFAULT_TREE

	/* we call a random event to obtain an event associated with this thread info */
	auto evt = generate_random_event(p2_t1_tid);
	/* The main thread is not included in the count */
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "2");

	/* removing the main thread doesn't change the count */
	evt = generate_proc_exit_event(p2_t1_tid, p2_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "2");

	/* This should decrement the count by 1 */
	evt = generate_proc_exit_event(p2_t3_tid, p2_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "1");

	/* we remove the thread group info from the thread so we should obtain a count equal to 0 */
	auto p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_TRUE(p2_t2_tinfo);
	p2_t2_tinfo->m_tginfo.reset();

	evt = generate_random_event(p2_t2_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "0");
}
