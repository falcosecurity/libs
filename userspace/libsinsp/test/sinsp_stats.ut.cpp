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
#ifdef __linux__

#include <gtest/gtest.h>
#include "sinsp_with_test_input.h"
#include <libsinsp/test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, sinsp_stats_v2_resource_utilization)
{
	m_inspector.set_sinsp_stats_v2_enabled();
	// Extra call to see we don't fail
	m_inspector.set_sinsp_stats_v2_enabled();
	// Adopted from test: TEST_F(sinsp_with_test_input, PROC_FILTER_nthreads)
	DEFAULT_TREE
	/* we call a random event to obtain an event associated with this thread info */
	auto evt = generate_random_event(p2_t1_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "3");

	const scap_agent_info* agent_info = m_inspector.get_agent_info();
	uint32_t nstats = 0;
	int32_t rc;
	const scap_stats_v2* sinsp_stats_v2_snapshot;
	auto buffer = m_inspector.get_sinsp_stats_v2_buffer();
    auto sinsp_stats_v2_counters = m_inspector.get_sinsp_stats_v2();
    sinsp_thread_manager* thread_manager = m_inspector.m_thread_manager.get();
	uint32_t flags = 0;
	sinsp_stats_v2_snapshot = libsinsp::stats::get_sinsp_stats_v2(flags, agent_info, thread_manager, sinsp_stats_v2_counters, buffer, &nstats, &rc);
    ASSERT_EQ(nstats, 0);
    ASSERT_EQ(rc, SCAP_SUCCESS);
	/* Extra call */
	flags |= PPM_SCAP_STATS_RESOURCE_UTILIZATION;
    sinsp_stats_v2_snapshot = libsinsp::stats::get_sinsp_stats_v2(flags, agent_info, thread_manager, sinsp_stats_v2_counters, buffer, &nstats, &rc);
    ASSERT_EQ(nstats, SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST + 1);
    ASSERT_EQ(rc, SCAP_SUCCESS);

    flags = (PPM_SCAP_STATS_RESOURCE_UTILIZATION | PPM_SCAP_STATS_STATE_COUNTERS);
	sinsp_stats_v2_snapshot = libsinsp::stats::get_sinsp_stats_v2(flags, agent_info, thread_manager, sinsp_stats_v2_counters, buffer, &nstats, &rc);
    ASSERT_EQ(nstats, SINSP_MAX_STATS_V2);
    ASSERT_EQ(rc, SCAP_SUCCESS);

    /* These names should always be available */
	std::unordered_set<std::string> minimal_stats_names = {"cpu_usage_perc", "memory_rss", "open_fds_host", "n_threads", "n_fds", "n_added_fds", "n_added_threads", "n_removed_threads", "n_containers"};

	uint32_t i = 0;
	for(const auto& stat_name : minimal_stats_names)
	{
		for(i = 0; i < nstats; i++)
		{
			if(stat_name.compare(sinsp_stats_v2_snapshot[i].name) == 0)
			{
				break;
			}
		}

		if(i == nstats)
		{
			FAIL() << "unable to find stat '" << stat_name << "' in the sinsp_stats_v2 buffer";
		}
	}

    /* Assert values are greater than 0 */
	ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].value.u32, 0);
    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].value.u32, 0);
	ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].value.d, 0);	
	ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].value.u64, 0);
    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].value.u32, 0);	
    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].value.u64, 0);

    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_STATS_V2_N_THREADS].value.u64, 0);
    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_STATS_V2_N_FDS].value.u64, 0);
    ASSERT_GT(sinsp_stats_v2_snapshot[SINSP_STATS_V2_ADDED_THREADS].value.u64, 0);

    /* Empty call */
    nstats = 0;
    flags = 0;
    sinsp_stats_v2_snapshot = libsinsp::stats::get_sinsp_stats_v2(flags, agent_info, thread_manager, sinsp_stats_v2_counters, buffer, &nstats, &rc);
    ASSERT_EQ(nstats, 0);
    ASSERT_EQ(rc, SCAP_SUCCESS);
}
#endif
