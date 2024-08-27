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

TEST(scap_file_kexec_arm64, tail_lineage)
{
	std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + std::string("kexec_arm64.scap");
	sinsp m_inspector;
	m_inspector.open_savefile(path);

	/* Check that containerd_shim main at the beginning is not a reaper since we cannot recover
	 * that info from proc scan.
	 */
	auto containerd_shim1_tinfo = m_inspector.get_thread_ref(141207);
	ASSERT_TRUE(containerd_shim1_tinfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo);
	ASSERT_FALSE(containerd_shim1_tinfo->m_tginfo->is_reaper());

	/* Search the tail execve event */
	int64_t tid_tail = 141546;
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

	/* In this captures all runc threads are already dead when we call tail so the expected lineage is the
	 * following:
	 *
	 * (num_event: 274503)
	 * v [tail] tid: 141546, pid: 141546, ptid 141446, vtid: 21, vpid: 21, reaper: 0
	 * v [bash] tid: 141446, pid: 141446, ptid: 141207, vtid: 14, vpid: 14, reaper: 0
	 * v [containerd-shim] tid: 141207, pid: 141207, ptid: 112983, vtid: 3910, vpid: 3910, reaper: 1
	 * v [systemd] tid: 112983, pid: 112983, ptid: 112962, vtid: 1, vpid: 1, reaper: 1
	 * v [containerd-shim] tid: 112962, pid: 112962, ptid: 1, vtid: 112962, vpid: 112962, reaper: 0
	 * v [systemd] tid: 1, pid: 1, ptid: 0, vtid: 1, vpid: 1, reaper: 1
	 */

	/* This is the process lineage we expect */
	int64_t tid_sh = 141446;
	int64_t tid_containerd_shim1 = 141207;
	int64_t tid_systemd1 = 112983;
	int64_t tid_containerd_shim2 = 112962;
	int64_t tid_systemd2 = 1;

	std::vector<int64_t> expected_traverse_parents_after_execve = {tid_sh, tid_containerd_shim1, tid_systemd1,
								       tid_containerd_shim2, tid_systemd2};
	traverse_parents.clear();
	ASSERT_TRUE(evt->get_thread_info());
	evt->get_thread_info()->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_traverse_parents_after_execve);

	/* At the beninning of the capture containerd_shim1 was not a reaper */
	containerd_shim1_tinfo = m_inspector.get_thread_ref(tid_containerd_shim1);
	ASSERT_TRUE(containerd_shim1_tinfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo);
	ASSERT_TRUE(containerd_shim1_tinfo->m_tginfo->is_reaper());
}

TEST(scap_file_kexec_arm64, final_thread_table_dim)
{
	std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + std::string("kexec_arm64.scap");
	sinsp m_inspector;
	m_inspector.open_savefile(path);

	/* Get the final event of the capture and check the thread_table dim */
	scap_file_test_helpers::capture_search_evt_by_num(&m_inspector, 907459);
	ASSERT_EQ(m_inspector.m_thread_manager->get_thread_count(), 612);
}
