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
	uint32_t test_metrics_flags = (METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS | METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	bool convert_memory_to_mb = true;
	std::unique_ptr<libsinsp::metrics::metrics_collector> metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	auto metrics_snapshot = metrics_collector->get_metrics();
	/* Multiple calls */
	metrics_collector->snapshot();
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* These names should always be available, note that we currently can't check for the merged scap stats metrics here */
	std::unordered_set<std::string> minimal_metrics_names = {"cpu_usage_perc", "memory_rss", "open_fds_host", \
	"n_threads", "n_fds", "n_added_fds", "n_added_threads", "n_removed_threads", "n_containers"};

	for(const auto& metric_name : minimal_metrics_names)
	{
		uint32_t i = 0;
		for (const auto& metric: metrics_snapshot) 
		{
			if(metric_name.compare(metric.name) == 0)
			{
				break;
			}
			i++;
		}
		if(i == metrics_snapshot.size())
		{
			FAIL() << "unable to find stat '" << metric_name << "' in metrics_snapshot buffer";
		}
	}

	/* Assert successful memory unit changes and sanity check some values to be greater than 0 */
	const std::vector<std::string> metrics_names_memory = {"memory_rss", "memory_vsz", "memory_pss", "container_memory_used", "memory_used_host"};
	const std::vector<std::string> metrics_names_values_gt = {"n_threads", "n_fds", "n_added_threads"};
	uint32_t success_memory_cnt = 0;
	uint32_t success_values_cnt = 0;
	for (const auto& metric: metrics_snapshot)
	{
		if (std::find(metrics_names_memory.begin(), metrics_names_memory.end(), metric.name) != metrics_names_memory.end())
		{
			ASSERT_EQ(metric.unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES);
			ASSERT_EQ(metric.type, METRIC_VALUE_TYPE_D);
			if (strncmp(metric.name, "memory_used_host", 17) == 0 || strncmp(metric.name, "memory_rss", 11) == 0 )
			{
				ASSERT_GT(metric.value.d, 0);
				// Just making sure we don't get a high value due to an unitialized variables
				ASSERT_LT(metric.value.d, 1000000);
				success_memory_cnt++;
			} else
			{
				success_memory_cnt++;
			}
		}
		if (std::find(metrics_names_values_gt.begin(), metrics_names_values_gt.end(), metric.name) != metrics_names_values_gt.end())
		{
			ASSERT_GT(metric.value.u64, 0);
			// Just making sure we don't get a high value due to an unitialized variables
			ASSERT_LT(metric.value.u64, 106721347371);
			success_values_cnt++;
		}
	}
	ASSERT_EQ(success_memory_cnt, metrics_names_memory.size());
	ASSERT_EQ(success_values_cnt, metrics_names_values_gt.size());

	/* Empty call */
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, 0, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Sanity check empty inspector */
	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(nullptr, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Some sanity checks for selective flags */
	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_KERNEL_COUNTERS; // 20, but can't test it here it's 0
	test_metrics_flags |= METRICS_V2_LIBBPF_STATS; // 21 (x86_64 machine), but can't test it here it's 0
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_RESOURCE_UTILIZATION;
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 9);

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_STATE_COUNTERS;
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 19);

	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	metrics_collector = std::make_unique<libsinsp::metrics::metrics_collector>(&m_inspector, test_metrics_flags, convert_memory_to_mb);
	metrics_collector->snapshot();
	metrics_snapshot = metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* Test public convert_memory method */
	double converted_memory = metrics_collector->convert_memory(METRIC_VALUE_UNIT_MEMORY_BYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)52428800);
	ASSERT_EQ(converted_memory, 50);
	converted_memory = metrics_collector->convert_memory(METRIC_VALUE_UNIT_MEMORY_KILOBYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)51200);
	ASSERT_EQ(converted_memory, 50);
	converted_memory = metrics_collector->convert_memory(METRIC_VALUE_UNIT_MEMORY_MEGABYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)50);
	ASSERT_EQ(converted_memory, 50);

}
#endif
