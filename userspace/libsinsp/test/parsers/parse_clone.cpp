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

/*=============================== CLONE CALLER EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, CLONE_CALLER_failed)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t p1_t1_tid = -3;

	/* Here we generate a parent clone exit event failed */
	evt = generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Since we are the father we should have a thread-info associated even if the clone failed
	 */
	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_tid, INIT_TID);
	ASSERT_EQ(evt->get_thread_info()->m_pid, INIT_PID);
	ASSERT_EQ(evt->get_thread_info()->m_ptid, INIT_PTID);

	/* We should have a NULL pointer here so no thread-info for the new process */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_FALSE(p1_t1_tinfo);
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* Parse a PPME_SYSCALL_CLONE_20_X event with the parent into a container */
	int64_t p1_t1_tid = 24;

	/* Flag `PPM_CL_CHILD_IN_PIDNS` is not set in this case by our drivers!
	 * Only `PPM_CL_CLONE_NEWPID`.
	 */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, PPM_CL_CLONE_NEWPID);

	/* The child process is in a container so the parent doesn't populate the thread_info for
	 * the child  */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_FALSE(p1_t1_tinfo);
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_tid_collision)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event but we remove the `PPM_CL_CLONE_INVERTED` flag
	 * in this way the parent clone event should remove it considering the entry stale
	 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event, we set a comm to understand if the final thread_info is overwritten or no */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Remove the `PPM_CL_CLONE_INVERTED` flag */
	p1_t1_tinfo->m_flags = p1_t1_tinfo->m_flags & ~PPM_CL_CLONE_INVERTED;

	/* Parent clone exit event */
	/* The parent considers the existing child entry stale and removes it.
	 * It will populate a new thread info
	 */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new_bash");

	p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	/* We should find the new name now since this should be a fresh thread info */
	ASSERT_EQ(p1_t1_tinfo->m_comm, "new_bash");
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_keep_existing_child)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event this should be preserved by the parent
	 * since we don't remove the `PPM_CL_CLONE_INVERTED` flag this time.
	 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new_bash");

	p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_new_main_thread)
{
	add_default_init_thread();
	open_inspector();

	/* We create this tree:
	 * - init
	 *  - p1_t1
	 */

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_flag_CLONE_PARENT)
{
	add_default_init_thread();
	open_inspector();

	/* We create this tree
	 * - init
	 *  - p1_t1
	 *  - p2_t1 (created with PPM_CL_CLONE_PARENT)
	 */

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second process p2 with the `CLONE_PARENT` flag */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	/* with the `CLONE_PARENT` flag the parent is the parent of the calling process */
	int64_t p2_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	/* When the caller event has the `PPM_CL_CLONE_PARENT` flag, it leaves to the child parser
	 * the honor to create the thread info for the child.
	 */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_PARENT);
	ASSERT_MISSING_THREAD_INFO(p2_t1_tid, true);

	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_PARENT);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)

	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLONE_PARENT, true);

	/* Assert that init has 2 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p2_t1_tid)
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_flag_CLONE_THREAD)
{
	add_default_init_thread();
	open_inspector();

	/* We create this tree:
	 * - init
	 *  - p1_t1
	 *  - p1_t2
	 */

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 25;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);

	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_THREAD, true);
	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_FILES, true);
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_check_event_tinfo)
{
	add_default_init_thread();
	open_inspector();

	/* Here we check that the clone parser sets the `event->mtinfo` in different cases. */

	/* New main thread, caller already present */
	auto evt = generate_clone_x_event(11, 1, 1, 0);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 1);

	/* New main thread, caller not already present */
	evt = generate_clone_x_event(13, 24, 24, 26);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 24);

	/* New thread */
	evt = generate_clone_x_event(14, 33, 32, 30, PPM_CL_CLONE_THREAD);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 33);

	/* New main thread container init */
	evt = generate_clone_x_event(15, 37, 37, 36, PPM_CL_CLONE_NEWNS);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 37);

	/* Caller in container */
	evt = generate_clone_x_event(2, 38, 38, 37, PPM_CL_CHILD_IN_PIDNS);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 38);
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_missing_both_clone_events_create_leader_thread)
{
	/* The schema is:
	 * - init
	 *  - p1_t1
	 *   - p2_t1 (we miss this thread info)
	 *    - p3_t1
	 */

	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* The process p1 creates a second process p2 but we miss both clone events (child, caller) so we know nothing
	 * about it */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_tid;

	/* The process p2 creates a new process p3 */
	int64_t p3_t1_tid = 50;
	int64_t p3_t1_pid = 50;
	int64_t p3_t1_ptid = p2_t1_tid;

	/* We use the clone caller exit event */
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid);

	/* We should have created a valid thread info for p2_t1 */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid);
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_missing_both_clone_events_create_secondary_threads)
{
	/* The schema is:
	 * - init
	 *  - p1_t1 (we miss this thread info)
	 *  - p1_t2
	 */

	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 but we miss both clone events so we know nothing about it */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_TID;

	/* We use the clone caller exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);

	/* We should have created a valid thread info for p1_t1 */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);

	/* We create also the new child of course */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
}

TEST_F(sinsp_with_test_input, CLONE_CALLER_comm_update)
{
	add_default_init_thread();

	/* Create process p1_t1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid, "old-name");

	open_inspector();

	/* Now imagine that process p1 calls a prctl and changes its name... */

	/* p1_t1 create a new process p2_t1. The clone caller exit event contains the new comm and should update the
	 * comm of p1
	 */

	int64_t p2_t1_tid = 26;
	[[maybe_unused]] int64_t p2_t1_pid = 26;
	[[maybe_unused]] int64_t p2_t1_ptid = p1_t1_tid;

	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "old-name");
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new-name");
	/* The caller has a new comm but we don't catch it! */
	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "old-name");

	/* The child will have the new comm */
	ASSERT_THREAD_INFO_COMM(p2_t1_tid, "new-name");
}

/*=============================== CLONE CALLER EXIT EVENT ===========================*/

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, CLONE_CHILD_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* We simulate a child clone exit event that wants to generate a child into a container */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;
	int64_t p1_t1_vtid = 80;
	int64_t p1_t1_vpid = 80;

	/* Child clone exit event */
	/* if we use `sched_proc_fork` tracepoint `PPM_CL_CLONE_NEWPID` won't be sent so we don't
	 * use it here, we use just `PPM_CL_CHILD_IN_PIDNS`
	 */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_t1_vtid, p1_t1_vpid);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p1_t1_tid, p1_t1_pid, p1_t1_ptid, p1_t1_vtid, p1_t1_vpid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_already_there)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Now we try to create a child with a different pid but
	 * same tid with a clone exit child event. We use a child
	 * with a new pid to understand if we use the old entry or a new one
	 * is created.
	 */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, p1_t1_tid, new_pid, p1_t1_ptid);

	/* The child parser should find a valid `evt->get_tinfo()` set by the previous
	 * parent clone event, so this new child event should be ignored and so
	 * the pid shouldn't be updated
	 */
	ASSERT_TRUE(evt);
	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pid, p1_t1_pid);
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_tid_collision)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* Create a mock child with a clone exit parent event */
	int64_t p1_t1_tid = 24;
	[[maybe_unused]] int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Now we taint the child thread info `clone_ts`, in this way when the
	 * clone child exit event will be called we should treat the current thread info
	 * as stale.
	 */
	tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	tinfo->m_clone_ts = tinfo->m_clone_ts - (CLONE_STALE_TIME_NS + 1);

	/* Now we try to create a child with a different pid but
	 * same tid with a clone exit child event. We use a child
	 * with a new pid to understand if we use the old entry or a new one
	 * is created.
	 */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, p1_t1_tid, new_pid, p1_t1_ptid);

	/* The child parser should find a "stale" `evt->get_tinfo()` set by the previous
	 * parent clone event and should replace it with new thread info.
	 */
	ASSERT_TRUE(evt);
	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pid, new_pid);
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_new_main_thread)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	evt = generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo, evt->get_thread_info());
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_flag_CLONE_PARENT)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* process p1 creates a new process p2 with the `CLONE_PARENT` flag */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = INIT_PID;

	/* Child clone exit event */
	/* Please note that in the clone child exit event, it could happen that
	 * we don't have the `PPM_CL_CLONE_PARENT` flag because the event could
	 * be generated by the `sched_proc_fork` tracepoint. BTW the child parser
	 * shouldn't need this flag to detect the real parent, so we omit it here
	 * and see what happens.
	 */
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid); // omitted PPM_CL_CLONE_PARENT
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p2_t1_tid)

	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLONE_PARENT, false);
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_flag_CLONE_THREAD)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* process p1 creates a new thread (p1_t2_tid) */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID;

	// /* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_THREAD, true);
	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_FILES, true);
}

TEST_F(sinsp_with_test_input, CLONE_CHILD_check_event_tinfo)
{
	add_default_init_thread();
	open_inspector();

	/* Here we check that the clone parser sets the `event->mtinfo` in different cases. */

	/* New main thread, caller already present */
	auto evt = generate_clone_x_event(0, 11, 11, 1);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 11);

	/* New main thread, caller not already present */
	evt = generate_clone_x_event(0, 24, 24, 26);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 24);

	/* New thread */
	evt = generate_clone_x_event(0, 33, 32, 30, PPM_CL_CLONE_THREAD);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 33);

	/* New main thread container init */
	evt = generate_clone_x_event(0, 37, 37, 36, PPM_CL_CLONE_NEWNS | PPM_CL_CHILD_IN_PIDNS);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 37);

	/* container */
	evt = generate_clone_x_event(0, 38, 38, 37, PPM_CL_CHILD_IN_PIDNS);
	ASSERT_TRUE(evt->get_tinfo());
	ASSERT_FALSE(evt->get_tinfo_ref());
	ASSERT_EQ(evt->get_tinfo()->m_tid, 38);
}

/* Here we are using the child clone exit event to reconstruct the tree */
TEST_F(sinsp_with_test_input, CLONE_CHILD_missing_both_clone_events_create_secondary_threads)
{
	/* The schema is:
	 * - init
	 *  - p1_t1 (we miss this thread info)
	 *  - p1_t2
	 */

	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 but we miss both clone events so we know nothing about it */
	int64_t p1_t1_tid = 24;
	[[maybe_unused]] int64_t p1_t1_pid = 24;
	[[maybe_unused]] int64_t p1_t1_ptid = INIT_TID;

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_TID;

	/* We use the clone child exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);

	/* We should have created a valid thread info for p1_t1 */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);

	/* We create also the new child of course */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
}

/*=============================== CLONE CHILD EXIT EVENT ===========================*/
