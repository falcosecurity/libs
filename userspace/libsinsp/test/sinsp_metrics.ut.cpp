// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

TEST_F(sinsp_with_test_input, sinsp_metrics_collector)
{
	m_inspector.set_sinsp_stats_v2_enabled();
	// Extra call to verify that we don't fail
	m_inspector.set_sinsp_stats_v2_enabled();
	DEFAULT_TREE
	auto evt = generate_random_event(p2_t1_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "3");

	/* Snapshot current metrics and get the updated metrics_snapshot buffer */
	uint32_t test_metrics_flags = (PPM_SCAP_STATS_KERNEL_COUNTERS | PPM_SCAP_STATS_LIBBPF_STATS | PPM_SCAP_STATS_RESOURCE_UTILIZATION | PPM_SCAP_STATS_STATE_COUNTERS);
	std::unique_ptr<libsinsp::metrics::metrics_collector> metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, test_metrics_flags);
	metrics_collector->snapshot();
	auto metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* These names should always be available, note that we currently can't check for the merged scap stats metrics here */
	std::unordered_set<std::string> minimal_stats_names = {"cpu_usage_perc", "memory_rss", "open_fds_host", \
	"n_threads", "n_fds", "n_added_fds", "n_added_threads", "n_removed_threads", "n_containers"};

	for(const auto& stat_name : minimal_stats_names)
	{
		uint32_t i = 0;
		for (const auto& stat : metrics_snapshot) 
		{
			if(stat_name.compare(stat.name) == 0)
			{
				break;
			}
			i++;
		}
		if(i == metrics_snapshot.size())
		{
			FAIL() << "unable to find stat '" << stat_name << "' in metrics_snapshot buffer";
		}
	}

	/* Assert some values are greater than 0 */
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].value.u32, 0);
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].value.u32, 0);
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].value.d, 0);
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].value.u64, 0);
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].value.u32, 0);
	ASSERT_GT(metrics_snapshot[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].value.u64, 0);

	ASSERT_GT(metrics_snapshot[SINSP_STATS_V2_N_THREADS].value.u64, 0);
	ASSERT_GT(metrics_snapshot[SINSP_STATS_V2_N_FDS].value.u64, 0);
	ASSERT_GT(metrics_snapshot[SINSP_STATS_V2_ADDED_THREADS].value.u64, 0);

	/* Empty call */
	metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, 0);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 0);

	/* Just checking that we don't crash w/ selective flags */
	test_metrics_flags = 0;
	test_metrics_flags |= PPM_SCAP_STATS_KERNEL_COUNTERS; // 20, but can't test it here it's 0
	test_metrics_flags |= PPM_SCAP_STATS_LIBBPF_STATS; // 21 (x86_64 machine), but can't test it here it's 0
	metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, test_metrics_flags);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 0);

	test_metrics_flags = 0;
	test_metrics_flags |= PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, test_metrics_flags);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 9);

	test_metrics_flags = 0;
	test_metrics_flags |= PPM_SCAP_STATS_STATE_COUNTERS;
	metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, test_metrics_flags);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 19);

	test_metrics_flags = (PPM_SCAP_STATS_RESOURCE_UTILIZATION | PPM_SCAP_STATS_STATE_COUNTERS);
	metrics_collector = libsinsp::metrics::metrics_collector::create(&m_inspector, test_metrics_flags);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* Check we don't crash if inspector is invalid and verify metrics vector is cleared */
	test_metrics_flags = (PPM_SCAP_STATS_RESOURCE_UTILIZATION | PPM_SCAP_STATS_STATE_COUNTERS);
	metrics_collector = libsinsp::metrics::metrics_collector::create(nullptr, test_metrics_flags);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 0);

}
#endif
