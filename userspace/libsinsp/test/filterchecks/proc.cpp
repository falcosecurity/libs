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

TEST_F(sinsp_with_test_input, PROC_FILTER_trusted_exepath)
{
	DEFAULT_TREE

	/* Now we call an execve on p6_t1 */
	auto evt = generate_execve_enter_and_exit_event(0, p6_t1_tid, p6_t1_tid, p6_t1_pid, p6_t1_ptid, "/good-exe", "good-exe", "/usr/bin/bad-exe");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/good-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "good-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.trusted_exepath"), "/usr/bin/bad-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_exe_symlink"), "true");
}

/* Here we are simulating a partial trusted exepath obtained from BPF */
TEST_F(sinsp_with_test_input, PROC_FILTER_is_exe_symlink_partial_BPF_trusted_exepath)
{
	DEFAULT_TREE

	/* Now we call an execve on p6_t1 */
	auto evt = generate_execve_enter_and_exit_event(0, p6_t1_tid, p6_t1_tid, p6_t1_pid, p6_t1_ptid, "/usr/bin/too_long", "too_long", "/usr/bin/too_");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/usr/bin/too_long");
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "too_long");
	ASSERT_EQ(get_field_as_string(evt, "proc.trusted_exepath"), "/usr/bin/too_");
	/* We cannot say if it is a symlink or not so we prefer a false positive */
	ASSERT_EQ(get_field_as_string(evt, "proc.is_exe_symlink"), "true");
}

TEST_F(sinsp_with_test_input, PROC_FILTER_is_exe_symlink_false)
{
	DEFAULT_TREE

	/* Now we call an execve on p6_t1 */
	auto evt = generate_execve_enter_and_exit_event(0, p6_t1_tid, p6_t1_tid, p6_t1_pid, p6_t1_ptid, "/usr/bin/short", "too_long", "/usr/bin/short");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/usr/bin/short");
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "too_long");
	ASSERT_EQ(get_field_as_string(evt, "proc.trusted_exepath"), "/usr/bin/short");
	ASSERT_EQ(get_field_as_string(evt, "proc.is_exe_symlink"), "false");
}
