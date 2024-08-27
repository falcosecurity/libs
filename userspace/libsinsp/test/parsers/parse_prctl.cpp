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

/*=============================== PRCTL EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, PRCTL_failed)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* FAILED PPM_PR_SET_CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and shouldn't become it after the next call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2` but it fails */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)-1,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	/* p2_t2_pid shouldn't be a reaper */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* FAILED PPM_PR_GET_CHILD_SUBREAPER */

	/* Same thing for a failed prctl get */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)-1,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	/* p2_t2_pid shouldn't be a reaper */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* INVALID THREAD INFO */

	/* this time the prctl call is successful but we call it from an invalid thread.
	 * Our logic will generate an invalid thread info, but this shouldn't have a valid tginfo so nothing should
	 * happen.
	 */
	int64_t invalid_tid = 61004;
	add_event_advance_ts(increasing_ts(), invalid_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	sinsp_threadinfo* invalid_tid_tinfo = m_inspector.get_thread_ref(invalid_tid, false).get();
	ASSERT_TRUE(invalid_tid_tinfo);
	ASSERT_FALSE(invalid_tid_tinfo->m_tginfo);

	/* Unhandled prctl option */

	/* Nothing should happen */
	add_event_advance_ts(increasing_ts(), invalid_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0, PPM_PR_SET_NAME, "<NA>",
			     (int64_t)1);
}

TEST_F(sinsp_with_test_input, PRCTL_set_child_subreaper)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* SET CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and should become it after the next call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2`. Parameter 4 could
	 * be anything greater than 1.
	 */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)80);

	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, true, 3, 3);

	/* UNSET CHILD_SUBREAPER */

	/* Let's imagine `p2_t3` unset its group with a prctl call.
	 * Please note that the reaper status is shared between all the thread group
	 */
	add_event_advance_ts(increasing_ts(), p2_t3_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	/* p2_t2 group should have reaper==false */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);
}

TEST_F(sinsp_with_test_input, PRCTL_get_child_subreaper)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* SET CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and should become it after the next call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2` */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, true, 3, 3);

	/* UNSET CHILD_SUBREAPER */

	/* Let's imagine `p2_t3` unset its group with a prctl call */
	add_event_advance_ts(increasing_ts(), p2_t3_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	/* p2_t2 group should have reaper==false */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);
}

/*=============================== PRCTL EXIT EVENT ===========================*/
