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

TEST_F(sinsp_with_test_input, PROC_FILTER_nthreads)
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

TEST_F(sinsp_with_test_input, PROC_FILTER_exepath)
{
	DEFAULT_TREE

	/* Now we call an execve on p6_t1 */
	auto evt = generate_execve_enter_and_exit_event(0, p6_t1_tid, p6_t1_tid, p6_t1_pid, p6_t1_ptid, "/good-exe", "good-exe", "/usr/bin/bad-exe");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/usr/bin/bad-exe");
	ASSERT_EQ(get_field_as_string(evt, "proc.name"), "good-exe");
}

TEST_F(sinsp_with_test_input, PROC_FILTER_pexepath_aexepath)
{
	DEFAULT_TREE

	/* p3_t1 call execve to set an exepath */
	generate_execve_enter_and_exit_event(0, p3_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, "/p3_t1_exepath", "p3_t1", "/usr/bin/p3_t1_trusted_exepath");

	/* p4_t2 call execve to set an exepath */
	generate_execve_enter_and_exit_event(0, p4_t2_tid, p4_t1_tid, p4_t1_pid, p4_t1_ptid, "/p4_t1_exepath", "p4_t1", "/usr/bin/p4_t1_trusted_exepath");

	/* p5_t2 call execve to set an exepath */
	generate_execve_enter_and_exit_event(0, p5_t2_tid, p5_t1_tid, p5_t1_pid, p5_t1_ptid, "/p5_t1_exepath", "p5_t1", "/usr/bin/p5_t1_trusted_exepath");

	/* Now we call an execve on p6_t1 and we check for `pexepath` and `aexepath` */
	auto evt = generate_execve_enter_and_exit_event(0, p6_t1_tid, p6_t1_tid, p6_t1_pid, p6_t1_ptid, "/p6_t1_exepath", "p6_t1", "/usr/bin/p6_t1_trusted_exepath");

	ASSERT_EQ(get_field_as_string(evt, "proc.exepath"), "/usr/bin/p6_t1_trusted_exepath");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[0]"), "/usr/bin/p6_t1_trusted_exepath");
	ASSERT_EQ(get_field_as_string(evt, "proc.pexepath"), "/usr/bin/p5_t1_trusted_exepath");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[1]"), get_field_as_string(evt, "proc.pexepath"));
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[2]"), "/usr/bin/p4_t1_trusted_exepath");
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[3]"), "/usr/bin/p3_t1_trusted_exepath");
	/* p2_t1 never calls an execve so it takes the exepath from `init` */
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[4]"), "/sbin/init");
	/* `init` exepath */
	ASSERT_EQ(get_field_as_string(evt, "proc.aexepath[5]"), "/sbin/init");
	/* this field shouldn't exist */
	ASSERT_FALSE(field_has_value(evt, "proc.aexepath[6]"));
}
