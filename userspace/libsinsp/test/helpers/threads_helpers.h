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
#pragma once

#include <gtest/gtest.h>
#include <sinsp_with_test_input.h>

#define HUGE_THREAD_NUMBER 150

#define ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ptid, vtid, vpid)                                               \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false, true).get();                          \
		ASSERT_TRUE(tinfo);                                                                                    \
		ASSERT_EQ(tinfo->m_tid, tid);                                                                          \
		ASSERT_EQ(tinfo->m_pid, pid);                                                                          \
		ASSERT_EQ(tinfo->m_ptid, ptid);                                                                        \
		ASSERT_EQ(tinfo->m_vtid, vtid);                                                                        \
		ASSERT_EQ(tinfo->m_vpid, vpid);                                                                        \
		ASSERT_EQ(tinfo->is_main_thread(), tinfo->m_tid == tinfo->m_pid);                                      \
	}

#define ASSERT_THREAD_INFO_PIDS(tid, pid, ppid)                                                                        \
	{                                                                                                              \
		ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ppid, tid, pid)                                         \
	}

#define ASSERT_THREAD_GROUP_INFO(tg_pid, alive_threads, reaper_enabled, threads_num, not_expired, ...)                 \
	{                                                                                                              \
		auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(tg_pid).get();                       \
		ASSERT_TRUE(tginfo);                                                                                   \
		ASSERT_EQ(tginfo->get_thread_count(), alive_threads);                                                  \
		ASSERT_EQ(tginfo->is_reaper(), reaper_enabled);                                                        \
		ASSERT_EQ(tginfo->get_tgroup_pid(), tg_pid);                                                           \
		ASSERT_EQ(tginfo->get_thread_list().size(), threads_num);                                              \
		std::set<int64_t> tid_to_assert{__VA_ARGS__};                                                          \
		for(const auto& tid : tid_to_assert)                                                                   \
		{                                                                                                      \
			sinsp_threadinfo* tid_tinfo = m_inspector.get_thread_ref(tid, false, true).get();              \
			ASSERT_TRUE(tid_tinfo);                                                                        \
			ASSERT_EQ(tid_tinfo->m_pid, tg_pid) << "Thread '" + std::to_string(tid_tinfo->m_tid) +         \
								       "' doesn't belong to the thread group id '" +   \
								       std::to_string(tg_pid) + "'";                   \
			bool found = false;                                                                            \
			for(const auto& thread : tginfo->get_thread_list())                                            \
			{                                                                                              \
				if(thread.lock().get() == tid_tinfo)                                                   \
				{                                                                                      \
					found = true;                                                                  \
				}                                                                                      \
			}                                                                                              \
			ASSERT_TRUE(found);                                                                            \
		}                                                                                                      \
		uint64_t not_expired_count = 0;                                                                        \
		for(const auto& thread : tginfo->get_thread_list())                                                    \
		{                                                                                                      \
			if(!thread.expired())                                                                          \
			{                                                                                              \
				not_expired_count++;                                                                   \
			}                                                                                              \
		}                                                                                                      \
		ASSERT_EQ(not_expired_count, not_expired);                                                             \
	}

#define ASSERT_THREAD_CHILDREN(parent_tid, children_num, not_expired, ...)                                             \
	{                                                                                                              \
		sinsp_threadinfo* parent_tinfo = m_inspector.get_thread_ref(parent_tid, false, true).get();            \
		ASSERT_TRUE(parent_tinfo);                                                                             \
		ASSERT_EQ(parent_tinfo->m_children.size(), children_num);                                              \
		std::set<int64_t> tid_to_assert{__VA_ARGS__};                                                          \
		for(const auto& tid : tid_to_assert)                                                                   \
		{                                                                                                      \
			sinsp_threadinfo* tid_tinfo = m_inspector.get_thread_ref(tid, false, true).get();              \
			ASSERT_TRUE(tid_tinfo);                                                                        \
			bool found = false;                                                                            \
			for(const auto& child : parent_tinfo->m_children)                                              \
			{                                                                                              \
				if(child.lock().get() == tid_tinfo)                                                    \
				{                                                                                      \
					found = true;                                                                  \
				}                                                                                      \
			}                                                                                              \
			ASSERT_TRUE(found);                                                                            \
		}                                                                                                      \
		uint16_t not_expired_count = 0;                                                                        \
		for(const auto& child : parent_tinfo->m_children)                                                      \
		{                                                                                                      \
			if(!child.expired())                                                                           \
			{                                                                                              \
				not_expired_count++;                                                                   \
			}                                                                                              \
		}                                                                                                      \
		ASSERT_EQ(not_expired_count, not_expired);                                                             \
		ASSERT_EQ(not_expired_count, parent_tinfo->m_not_expired_children);                                    \
	}

/* if `missing==true` we shouldn't find the thread info */
#define ASSERT_MISSING_THREAD_INFO(tid_to_check, missing)                                                              \
	{                                                                                                              \
		if(missing)                                                                                            \
		{                                                                                                      \
			ASSERT_FALSE(m_inspector.get_thread_ref(tid_to_check, false));                                 \
		}                                                                                                      \
		else                                                                                                   \
		{                                                                                                      \
			ASSERT_TRUE(m_inspector.get_thread_ref(tid_to_check, false));                                  \
		}                                                                                                      \
	}

#define ASSERT_THREAD_INFO_FLAG(tid, flag, present)                                                                    \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false, true).get();                          \
		ASSERT_TRUE(tinfo);                                                                                    \
		if(present)                                                                                            \
		{                                                                                                      \
			ASSERT_TRUE(tinfo->m_flags& flag);                                                             \
		}                                                                                                      \
		else                                                                                                   \
		{                                                                                                      \
			ASSERT_FALSE(tinfo->m_flags& flag);                                                            \
		}                                                                                                      \
	}

#define ASSERT_THREAD_INFO_COMM(tid, comm)                                                                             \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false).get();                                \
		ASSERT_TRUE(tinfo);                                                                                    \
		ASSERT_EQ(tinfo->m_comm, comm);                                                                        \
	}

#define DEFAULT_TREE_NUM_PROCS 12

/* This is the default tree:
 *	- (init) tid 1 pid 1 ptid 0
 *  - (p_1 - t1) tid 2 pid 2 ptid 1
 *  - (p_1 - t2) tid 3 pid 2 ptid 1
 * 	 - (p_2 - t1) tid 25 pid 25 ptid 1 (CLONE_PARENT)
 * 	  - (p_3 - t1) tid 72 pid 72 ptid 25
 * 	   - (p_4 - t1) tid 76 pid 76 ptid 72 (container: vtid 1 vpid 1)
 * 	   - (p_4 - t2) tid 79 pid 76 ptid 72 (container: vtid 2 vpid 1)
 * 		- (p_5 - t1) tid 82 pid 82 ptid 79 (container: vtid 10 vpid 10)
 * 		- (p_5 - t2) tid 84 pid 82 ptid 79 (container: vtid 12 vpid 10)
 *  	 - (p_6 - t1) tid 87 pid 87 ptid 84 (container: vtid 17 vpid 17)
 * 	 - (p_2 - t2) tid 23 pid 25 ptid 1
 * 	 - (p_2 - t3) tid 24 pid 25 ptid 1
 */
#define DEFAULT_TREE                                                                                                   \
	add_default_init_thread();                                                                                     \
	open_inspector();                                                                                              \
                                                                                                                       \
	/* Init process creates a child process */                                                                     \
                                                                                                                       \
	/*=============================== p1_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p1_t1_tid = 2;                                                                        \
	[[maybe_unused]] int64_t p1_t1_pid = p1_t1_tid;                                                                \
	[[maybe_unused]] int64_t p1_t1_ptid = INIT_TID;                                                                \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);                                              \
                                                                                                                       \
	/*=============================== p1_t1 ===========================*/                                          \
                                                                                                                       \
	/* p1 process creates a second thread */                                                                       \
                                                                                                                       \
	/*=============================== p1_t2 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p1_t2_tid = 6;                                                                        \
	[[maybe_unused]] int64_t p1_t2_pid = p1_t1_pid;                                                                \
	[[maybe_unused]] int64_t p1_t2_ptid = INIT_TID;                                                                \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p1_t2 ===========================*/                                          \
                                                                                                                       \
	/* The second thread of p1 create a new process p2 */                                                          \
                                                                                                                       \
	/*=============================== p2_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p2_t1_tid = 25;                                                                       \
	[[maybe_unused]] int64_t p2_t1_pid = 25;                                                                       \
	[[maybe_unused]] int64_t p2_t1_ptid = INIT_TID;                                                                \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_PARENT);                      \
	/* Here we need also the child exit event because the caller doesn't generate*/                                \
	/* the child thread info if we use the `PPM_CL_CLONE_PARENT` flag due to runc! */                              \
	/* See the clone_parser code. */                                                                               \
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_PARENT);                              \
                                                                                                                       \
	/*=============================== p2_t1 ===========================*/                                          \
                                                                                                                       \
	/* p2 process creates a second thread */                                                                       \
                                                                                                                       \
	/*=============================== p2_t2 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p2_t2_tid = 23;                                                                       \
	[[maybe_unused]] int64_t p2_t2_pid = p2_t1_pid;                                                                \
	[[maybe_unused]] int64_t p2_t2_ptid = INIT_TID; /* p2_t2 will have the same parent of p2_t1 */                 \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p2_t2 ===========================*/                                          \
                                                                                                                       \
	/* p2_t2 creates a new thread p2_t3 */                                                                         \
                                                                                                                       \
	/*=============================== p2_t3 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p2_t3_tid = 24;                                                                       \
	[[maybe_unused]] int64_t p2_t3_pid = p2_t1_pid;                                                                \
	[[maybe_unused]] int64_t p2_t3_ptid = INIT_TID;                                                                \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t3_tid, p2_t2_tid, p2_t2_pid, p2_t2_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p2_t3 ===========================*/                                          \
                                                                                                                       \
	/* The leader thread of p2 create a new process p3 */                                                          \
                                                                                                                       \
	/*=============================== p3_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p3_t1_tid = 72;                                                                       \
	[[maybe_unused]] int64_t p3_t1_pid = p3_t1_tid;                                                                \
	[[maybe_unused]] int64_t p3_t1_ptid = p2_t1_tid;                                                               \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);                                           \
                                                                                                                       \
	/*=============================== p3_t1 ===========================*/                                          \
                                                                                                                       \
	/* The leader thread of p3 create a new process p4 in a new container */                                       \
                                                                                                                       \
	/*=============================== p4_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p4_t1_tid = 76;                                                                       \
	[[maybe_unused]] int64_t p4_t1_pid = p4_t1_tid;                                                                \
	[[maybe_unused]] int64_t p4_t1_ptid = p3_t1_tid;                                                               \
	[[maybe_unused]] int64_t p4_t1_vtid = 1; /* This process will be the `init` one in the new namespace */        \
	[[maybe_unused]] int64_t p4_t1_vpid = p4_t1_vtid;                                                              \
                                                                                                                       \
	generate_clone_x_event(p4_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, PPM_CL_CLONE_NEWPID);                      \
                                                                                                                       \
	/* Check fields after parent parsing                                                                           \
	 * Note: here we cannot assert anything because the child will be in a container                               \
	 * and so the parent doesn't create the `thread-info` for the child.                                           \
	 */                                                                                                            \
                                                                                                                       \
	/* Child exit event */                                                                                         \
	/* On arm64 the flag `PPM_CL_CLONE_NEWPID` is not sent by the child, so we simulate the                        \
	 * worst case */                                                                                               \
	generate_clone_x_event(0, p4_t1_tid, p4_t1_pid, p4_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p4_t1_vtid, p4_t1_vpid);    \
                                                                                                                       \
	/*=============================== p4_t1 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p4_t2 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p4_t2_tid = 79;                                                                       \
	[[maybe_unused]] int64_t p4_t2_pid = p4_t1_pid;                                                                \
	[[maybe_unused]] int64_t p4_t2_ptid = p3_t1_tid;                                                               \
	[[maybe_unused]] int64_t p4_t2_vtid = 2;                                                                       \
	[[maybe_unused]] int64_t p4_t2_vpid = p4_t1_vpid;                                                              \
                                                                                                                       \
	generate_clone_x_event(0, p4_t2_tid, p4_t2_pid, p4_t2_ptid, PPM_CL_CLONE_THREAD | PPM_CL_CHILD_IN_PIDNS,       \
			       p4_t2_vtid, p4_t2_vpid);                                                                \
                                                                                                                       \
	/*=============================== p4_t2 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p5_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p5_t1_tid = 82;                                                                       \
	[[maybe_unused]] int64_t p5_t1_pid = p5_t1_tid;                                                                \
	[[maybe_unused]] int64_t p5_t1_ptid = p4_t2_tid;                                                               \
	[[maybe_unused]] int64_t p5_t1_vtid = 10;                                                                      \
	[[maybe_unused]] int64_t p5_t1_vpid = p5_t1_vtid;                                                              \
                                                                                                                       \
	generate_clone_x_event(0, p5_t1_tid, p5_t1_pid, p5_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p5_t1_vtid, p5_t1_vpid);    \
                                                                                                                       \
	/*=============================== p5_t1 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p5_t2 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p5_t2_tid = 84;                                                                       \
	[[maybe_unused]] int64_t p5_t2_pid = p5_t1_pid;                                                                \
	[[maybe_unused]] int64_t p5_t2_ptid = p4_t2_tid;                                                               \
	[[maybe_unused]] int64_t p5_t2_vtid = 12;                                                                      \
	[[maybe_unused]] int64_t p5_t2_vpid = p5_t1_vpid;                                                              \
                                                                                                                       \
	generate_clone_x_event(0, p5_t2_tid, p5_t2_pid, p5_t2_ptid, PPM_CL_CHILD_IN_PIDNS, p5_t2_vtid, p5_t2_vpid);    \
                                                                                                                       \
	/*=============================== p5_t2 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p6_t1 ===========================*/                                          \
                                                                                                                       \
	[[maybe_unused]] int64_t p6_t1_tid = 87;                                                                       \
	[[maybe_unused]] int64_t p6_t1_pid = p6_t1_tid;                                                                \
	[[maybe_unused]] int64_t p6_t1_ptid = p5_t2_tid;                                                               \
	[[maybe_unused]] int64_t p6_t1_vtid = 17;                                                                      \
	[[maybe_unused]] int64_t p6_t1_vpid = p6_t1_vtid;                                                              \
                                                                                                                       \
	generate_clone_x_event(0, p6_t1_tid, p6_t1_pid, p6_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p6_t1_vtid, p6_t1_vpid);    \
                                                                                                                       \
	/*=============================== p6_t1 ===========================*/
