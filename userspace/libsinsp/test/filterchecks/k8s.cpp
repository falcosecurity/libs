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

/* K8s filterchecks are not defined in the minimal build so we need this ifdef */
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
#include <test/helpers/threads_helpers.h>
TEST_F(sinsp_with_test_input, K8S_FILTER_pod_id)
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
	};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups1);
	scap_const_sized_buffer empty_bytebuf = {/*.buf =*/ nullptr, /*.size =*/ 0};
	auto evt = add_event_advance_ts(increasing_ts(), p1_tid, PPME_SYSCALL_CLONE_20_X, 21, 0, "init", empty_bytebuf, p1_tid, p1_pid, p1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, 0, not_relevant_32, not_relevant_32, p1_vtid, p1_vpid);

	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.id"), "05869489-8c7f-45dc-9abd-1b1620787bb1");
}

#endif
