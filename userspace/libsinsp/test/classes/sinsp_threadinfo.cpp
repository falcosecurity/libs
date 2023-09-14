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

TEST(sinsp_threadinfo, get_main_thread)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We are the main thread so here we don't use the thread group info */
	ASSERT_EQ(tinfo->get_main_thread(), tinfo.get());

	/* Now we change the tid so we are no more a main thread and we use the thread group info
	 * we should obtain a nullptr since tinfo doesn't have any thread group info associated.
	 */
	tinfo->m_tid = 25;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	/* We should still obtain a nullptr since the first tinfo in the thread group info is not a main thread. */
	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	/* We should still obtain a nullptr since we put the main thread as the last element of the list. */
	tinfo->m_tginfo->add_thread_to_group(main_tinfo, false);
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	tinfo->m_tginfo->add_thread_to_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_main_thread(), main_tinfo.get());
}

TEST(sinsp_threadinfo, get_num_threads)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 25;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* Thread info doesn't have an associated thread group info */
	ASSERT_EQ(tinfo->get_num_threads(), 0);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 0);

	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_num_threads(), 1);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	tinfo->m_tginfo->add_thread_to_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	/* 1 thread is the main thread so we should return just 1 */
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	main_tinfo->set_dead();

	/* Please note that here we still have 2 because we have just marked the thread as Dead without decrementing the
	 * alive count */
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 2);
}

TEST_F(sinsp_with_test_input, THRD_INFO_assign_children_to_reaper)
{
	DEFAULT_TREE

	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();

	/* The reaper cannot be the current process */
	EXPECT_THROW(p3_t1_tinfo->assign_children_to_reaper(p3_t1_tinfo), sinsp_exception);

	/* children of p3_t1 are p4_t1 and p4_t2 we can reparent them to p1_t1 for example */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 0, 0);

	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);

	/* all p3_t1 children should be removed */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);

	/* the new parent should be p1_t1 */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p1_t1_tid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p1_t1_tid, p4_t2_vtid, p4_t2_vpid);

	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);

	/* Another call to the reparenting function should do nothing since p3_t1 has no other children */
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_INFO_assign_children_to_a_nullptr)
{
	DEFAULT_TREE

	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	/* This call should change the parent of all children of p2_t1 to `0` */
	p2_t1_tinfo->assign_children_to_reaper(nullptr);

	ASSERT_THREAD_CHILDREN(p2_t1_tid, 0, 0);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, 0);
}

// This test asserts that our regex is solid against all possible cgroup layouts
TEST(sinsp_threadinfo, check_pod_uid_regex)
{
	// RGX_POD is defined in `threadinfo.h`
	re2::RE2 pattern(RGX_POD, re2::RE2::POSIX);

	// CgroupV1, driver cgroup
	std::string expected_pod_uid = "pod05869489-8c7f-45dc-9abd-1b1620787bb1";
	std::string actual_pod_uid = "";
	ASSERT_TRUE(re2::RE2::PartialMatch("/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc", pattern, &actual_pod_uid));
	ASSERT_EQ(expected_pod_uid, actual_pod_uid);

	// CgroupV1, driver systemd
	expected_pod_uid = "pod0f90f31c_ebeb_4192_a2b0_92e076c43817";
	ASSERT_TRUE(re2::RE2::PartialMatch("/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod0f90f31c_ebeb_4192_a2b0_92e076c43817.slice/4c97d83b89df14eea65dbbab1f506b405758341616ab75437d66fd8bab0e2beb", pattern, &actual_pod_uid));
	ASSERT_EQ(expected_pod_uid, actual_pod_uid);

	// CgroupV2, driver cgroup
	expected_pod_uid = "podaf4fa4cf-129e-4699-a2af-65548fb8977d";
	ASSERT_TRUE(re2::RE2::PartialMatch("/kubepods/besteffort/podaf4fa4cf-129e-4699-a2af-65548fb8977d/fc16540dcd776bb475437b722c47de798fa1b07687db1ba7d4609c23d5d1a088", pattern, &actual_pod_uid));
	ASSERT_EQ(expected_pod_uid, actual_pod_uid);

	// CgroupV2, driver systemd
	expected_pod_uid = "pod43f23404_e33c_48c7_8114_28ee4b7043ec";
	ASSERT_TRUE(re2::RE2::PartialMatch("/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod43f23404_e33c_48c7_8114_28ee4b7043ec.slice/cri-containerd-b59ce319955234d0b051a93dac5efa8fc07df08d8b0188195b434174efc44e73.scope", pattern, &actual_pod_uid));
	ASSERT_EQ(expected_pod_uid, actual_pod_uid);

	// Not match, wrong pod_uid format
	ASSERT_FALSE(re2::RE2::PartialMatch("cpuset=/kubepods/besteffort/pod05869489W-8c7fWW-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc", pattern));
}

// This test asserts that our parsers (clone/execve) can extract the pod_uid from cgroups.
TEST_F(sinsp_with_test_input, THRD_INFO_extract_pod_uid)
{
	add_default_init_thread();
	open_inspector();

	int64_t p1_tid = 2;
	int64_t p1_pid = 2;
	int64_t p1_ptid = INIT_TID;
	int64_t p1_vtid = 1;
	int64_t p1_vpid = 1;

	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;

	// cgroupfs driver format
	std::vector<std::string> cgroups1 = {
		"cpuset=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"cpu=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"cpuacct=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"io=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"memory=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"devices=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
		"freezer=/kubepods/besteffort/pod05869489-8c7f-45dc-9abd-1b1620787bb1/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bbc",
	};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups1);
	scap_const_sized_buffer empty_bytebuf = {/*.buf =*/ nullptr, /*.size =*/ 0};
	auto evt = add_event_advance_ts(increasing_ts(), p1_tid, PPME_SYSCALL_CLONE_20_X, 21, (int64_t)0, "init", empty_bytebuf, p1_tid, p1_pid, p1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (int32_t)0, not_relevant_32, not_relevant_32, p1_vtid, p1_vpid);

	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pod_uid, "05869489-8c7f-45dc-9abd-1b1620787bb1");

	// Now we simulate a change of cgroups in the execve event.

	// systemd driver format
	// Only one cgroup subsystem is enough
	std::vector<std::string> cgroups2 = {
		"cpuset=/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod47bf324a_ed3e_4a7c_be4a_7d119755bfcb.slice",
	};

	cgroupsv = test_utils::to_null_delimited(cgroups2);
	evt = add_event_advance_ts(increasing_ts(), p1_tid, PPME_SYSCALL_EXECVE_19_X, 28, (int64_t)0, "/bin/new-prog", empty_bytebuf, p1_tid, p1_pid, p1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "new-prog", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, empty_bytebuf, not_relevant_32, not_relevant_32, not_relevant_32, (int32_t) PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, "/bin/new-prog");

	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pod_uid, "47bf324a-ed3e-4a7c-be4a-7d119755bfcb");
}
