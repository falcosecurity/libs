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

TEST_F(sinsp_with_test_input, sinsp_libs_metrics_collector_prometheus)
{
	m_inspector.set_sinsp_stats_v2_enabled();
	// Extra call to verify that we don't fail
	m_inspector.set_sinsp_stats_v2_enabled();
	DEFAULT_TREE
	auto evt = generate_random_event(p2_t1_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "3");

	/* Snapshot current metrics and get the updated metrics_snapshot buffer */
	uint32_t test_metrics_flags = (METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS | METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	auto libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	auto prometheus_metrics_converter = std::make_unique<libs::metrics::prometheus_metrics_converter>();

	libs_metrics_collector->snapshot();
	auto metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* Test prometheus_metrics_converter->convert_metric_to_text */
	std::string prometheus_text;
	std::string prometheus_text_substring;
	for (const auto& metric: metrics_snapshot)
	{
		if (strncmp(metric.name, "n_missing_container_images", 17) == 0)
		{
			// This resembles the Falco client use case

			// Falco output_rule metrics prepends either `falco.` or `scap.` to a single metric, see https://falco.org/docs/metrics/
			// Use same strings for `prometheus_subsystem`, but instead of `.` we use `_` delimiter to conform with Prometheus naming conventions + append the unit
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "testns", "falco", {{"example_key1", "example1"},{"example_key2", "example2"}});
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images",example_key1="example1",example_key2="example2"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
			// Test only one const_labels
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "testns", "falco", {{"example_key1", "example1"}});
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images",example_key1="example1"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
			// Test no const_labels
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "testns", "falco");
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
			// Test no prometheus_subsytem
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "testns");
			prometheus_text_substring = R"(# HELP testns_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_n_missing_container_images_total gauge
testns_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
			// Test no prometheus_namespace
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric);
			prometheus_text_substring = R"(# HELP n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE n_missing_container_images_total gauge
n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
			//  Test no prometheus_namespace, but prometheus_subsytem
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "", "falco");
			prometheus_text_substring = R"(# HELP falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE falco_n_missing_container_images_total gauge
falco_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
		} else if (strncmp(metric.name, "memory_rss_kb", 16) == 0)
		{
			// Test that libs native metric unit suffix was removed and replaced by the Prometheus specific unit suffix naming convention
			// todo adjust once base units are implemented
			prometheus_text = prometheus_metrics_converter->convert_metric_to_text(metric, "testns", "falco");
			printf("%s", prometheus_text.c_str());
			prometheus_text_substring = R"(# HELP testns_falco_memory_rss_kibibytes https://falco.org/docs/metrics/
# TYPE testns_falco_memory_rss_kibibytes gauge
testns_falco_memory_rss_kibibytes{raw_name="memory_rss_kb"} )";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
			ASSERT_GT(prometheus_text.length(), 8);
		}
	}

	// Test global wrapper base metrics
	prometheus_text = prometheus_metrics_converter->convert_metric_to_text("kernel_release", "testns", "falco", {{"kernel_release", "6.6.7-200.fc39.x86_64"}});
	prometheus_text_substring = R"(# HELP testns_falco_kernel_release_info https://falco.org/docs/metrics/
# TYPE testns_falco_kernel_release_info gauge
testns_falco_kernel_release_info{raw_name="kernel_release",kernel_release="6.6.7-200.fc39.x86_64"} 1
)";
	ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text";
	ASSERT_GT(prometheus_text.length(), 8);
}

TEST_F(sinsp_with_test_input, sinsp_libs_metrics_collector_output_rule)
{
	m_inspector.set_sinsp_stats_v2_enabled();
	// Extra call to verify that we don't fail
	m_inspector.set_sinsp_stats_v2_enabled();
	DEFAULT_TREE
	auto evt = generate_random_event(p2_t1_tid);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "3");

	/* Snapshot current metrics and get the updated metrics_snapshot buffer */
	uint32_t test_metrics_flags = (METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS | METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	auto libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	auto output_rule_metrics_converter = std::make_unique<libs::metrics::output_rule_metrics_converter>();

	/* Multiple calls */
	libs_metrics_collector->snapshot();
	auto metrics_snapshot = libs_metrics_collector->get_metrics();
	libs_metrics_collector->snapshot();
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* These names should always be available, note that we currently can't check for the merged scap stats metrics here */
	std::unordered_set<std::string> minimal_metrics_names = {"cpu_usage_perc", "memory_rss_kb", "host_open_fds", \
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
	const std::vector<std::string> metrics_names_memory = {"memory_rss_mb", "memory_vsz_mb", "memory_pss_mb", "container_memory_used_mb", "host_memory_used_mb"};
	const std::vector<std::string> metrics_names_values_gt = {"n_threads", "n_fds", "n_added_threads"};
	uint32_t success_memory_cnt = 0;
	uint32_t success_values_cnt = 0;
	for (auto& metric: metrics_snapshot)
	{
		// This resembles the Falco client use case and would be called if `convert_memory_to_mb` is set to true
		output_rule_metrics_converter->convert_metric_to_unit_convention(metric);
		if (std::find(metrics_names_memory.begin(), metrics_names_memory.end(), metric.name) != metrics_names_memory.end())
		{
			ASSERT_EQ(metric.unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES);
			ASSERT_EQ(metric.type, METRIC_VALUE_TYPE_D);
			if (strncmp(metric.name, "host_memory_used_mb", 20) == 0 || strncmp(metric.name, "memory_rss_mb", 14) == 0 )
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
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, 0);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Sanity check empty inspector */
	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(nullptr, test_metrics_flags);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Some sanity checks for selective flags */
	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_KERNEL_COUNTERS; // 20, but can't test it here it's 0
	test_metrics_flags |= METRICS_V2_LIBBPF_STATS; // 21 (x86_64 machine), but can't test it here it's 0
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_RESOURCE_UTILIZATION;
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 9);

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_STATE_COUNTERS;
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 19);

	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	libs_metrics_collector = std::make_unique<libs::metrics::libs_metrics_collector>(&m_inspector, test_metrics_flags);
	libs_metrics_collector->snapshot();
	metrics_snapshot = libs_metrics_collector->get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);
}

TEST(sinsp_libs_metrics, sinsp_libs_metrics_convert_units)
{
	/* Test public libs::metrics::convert_memory method */
	double converted_memory = libs::metrics::convert_memory(METRIC_VALUE_UNIT_MEMORY_BYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)52428800);
	ASSERT_EQ(converted_memory, 50);
	converted_memory = libs::metrics::convert_memory(METRIC_VALUE_UNIT_MEMORY_KIBIBYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)51200);
	ASSERT_EQ(converted_memory, 50);
	converted_memory = libs::metrics::convert_memory(METRIC_VALUE_UNIT_MEMORY_MEGABYTES, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, (uint64_t)50);
	ASSERT_EQ(converted_memory, 50);
}

#endif
