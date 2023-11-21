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
#include <helpers/scap_file_helpers.h>

TEST(scap_file_kexec_x86, tail_lineage)
{
	std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + std::string("kexec_x86.scap");
	sinsp m_inspector;
	m_inspector.open_savefile(path);

	/* Check that containerd_shim main at the beginning is not a reaper since we cannot recover
	 * that info from proc scan.
	 */
	auto containerd_shim1_tinfo = m_inspector.get_thread_ref(107196);
	ASSERT_TRUE(containerd_shim1_tinfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo);
	ASSERT_FALSE(containerd_shim1_tinfo->m_tginfo->is_reaper());

	/* Search the tail execve event */
	int64_t tid_tail = 107370;
	auto evt = scap_file_test_helpers::capture_search_evt_by_type_and_tid(&m_inspector, PPME_SYSCALL_EXECVE_19_X,
									      tid_tail);

	std::vector<int64_t> traverse_parents;
	sinsp_threadinfo::visitor_func_t visitor = [&traverse_parents](sinsp_threadinfo* pt)
	{
		/* we stop when we reach the init parent */
		traverse_parents.push_back(pt->m_tid);
		if(pt->m_tid == INIT_TID)
		{
			return false;
		}
		return true;
	};

	/* First we will check tail lineage after tail execve event.
	 * This is what we expect because {runc}(107357) is not yet died.
	 * We will check again the tree after {runc}(107357) dies
	 *
	 * (num_event: 161211)
	 * v [tail] tid: 107370, pid: 107370, ptid 107364, vtid: 19, vpid: 19, reaper: 0
	 * v [sh] tid: 107364, pid: 107364, ptid: 107357, vtid: 13, vpid: 13, reaper: 0
	 * v {runc} tid: 107357, pid: 107354, ptid: 107204, vtid: 2019, vpid: 2016, reaper: 0
	 * v {containerd-shim} tid: 107204, pid: 107196, ptid: 100562, vtid: 1951, vpid: 1943, reaper: 0,
	 * v [systemd] tid: 100562, pid: 100562, ptid: 100542, vtid: 1, vpid: 1, reaper: 1,
	 * v [containerd-shim] tid: 100542, pid: 100542, ptid: 1, vtid: 100542, vpid: 100542, reaper: 0
	 * v [systemd] tid: 1, pid: 1, ptid: 0, vtid: 1, vpid: 1, reaper: 1
	 */

	/* This is the process lineage we expect */
	int64_t tid_sh = 107364;
	int64_t tid_runc = 107357;
	int64_t tid_containerd_shim1 = 107204;
	int64_t tid_systemd1 = 100562;
	int64_t tid_containerd_shim2 = 100542;
	int64_t tid_systemd2 = 1;

	std::vector<int64_t> expected_traverse_parents_after_execve = {
		tid_sh, tid_runc, tid_containerd_shim1, tid_systemd1, tid_containerd_shim2, tid_systemd2};
	traverse_parents.clear();
	ASSERT_TRUE(evt->get_thread_info());
	evt->get_thread_info()->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_traverse_parents_after_execve);

	/* At event num `161343` all runc threads are dead */
	evt = scap_file_test_helpers::capture_search_evt_by_num(&m_inspector, 161343);

	/* This should be the new father of [sh](107364) since it is a reaper */
	tid_containerd_shim1 = 107196;

	/* This is what we expect now:
	 *
	 * (num_event: 161343)
	 * v [tail] tid: 107370, pid: 107370, ptid 107364, vtid: 19, vpid: 19, reaper: 0
	 * v [sh] tid: 107364, pid: 107364, ptid: 107357, vtid: 13, vpid: 13, reaper: 0
	 * v [containerd-shim] tid: 107196, pid: 107196, ptid: 100562, vtid: 1943, vpid: 1943, reaper: 1
	 * v [systemd] tid: 100562, pid: 100562, ptid: 100542, vtid: 1, vpid: 1, reaper: 1,
	 * v [containerd-shim] tid: 100542, pid: 100542, ptid: 1, vtid: 100542, vpid: 100542, reaper: 0
	 * v [systemd] tid: 1, pid: 1, ptid: 0, vtid: 1, vpid: 1, reaper: 1
	 */

	std::vector<int64_t> expected_traverse_parents_after_remove = {tid_sh, tid_containerd_shim1, tid_systemd1,
								       tid_containerd_shim2, tid_systemd2};
	traverse_parents.clear();
	ASSERT_TRUE(evt->get_thread_info());
	evt->get_thread_info()->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_traverse_parents_after_remove);

	/* At the beninning of the capture containerd_shim1 was not a reaper */
	containerd_shim1_tinfo = m_inspector.get_thread_ref(tid_containerd_shim1);
	ASSERT_TRUE(containerd_shim1_tinfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo->is_reaper());
}

TEST(scap_file_kexec_x86, final_thread_table_dim)
{
	std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + std::string("kexec_x86.scap");
	sinsp m_inspector;
	m_inspector.open_savefile(path);

	/* Get the final event of the capture and check the thread_table dim */
	scap_file_test_helpers::capture_search_evt_by_num(&m_inspector, 523413);
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 558);
}
