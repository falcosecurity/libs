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
	libs::metrics::libs_metrics_collector libs_metrics_collector(&m_inspector, test_metrics_flags);
	libs::metrics::prometheus_metrics_converter prometheus_metrics_converter;

	libs_metrics_collector.snapshot();
	auto metrics_snapshot = libs_metrics_collector.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* Test prometheus_metrics_converter.convert_metric_to_text_prometheus */
	std::string prometheus_text;
	std::string prometheus_text_substring;
	std::string metrics_names_all_str_post_unit_conversion_pre_prometheus_text_conversion;

	for (auto& metric: metrics_snapshot)
	{
		prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
		if (!metrics_names_all_str_post_unit_conversion_pre_prometheus_text_conversion.empty())
		{
			metrics_names_all_str_post_unit_conversion_pre_prometheus_text_conversion += " ";
		}
		metrics_names_all_str_post_unit_conversion_pre_prometheus_text_conversion += metric.name;
		// Since unit testing is very limited here just also print it for manual inspection if needed
		prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco");
		std::cerr << prometheus_text;

		if (strncmp(metric.name, "n_missing_container_images", strlen(metric.name)) == 0)
		{
			// This resembles the Falco client use case

			// Falco output_rule metrics prepends either `falco.` or `scap.` to a single metric, see https://falco.org/docs/metrics/
			// Use same strings for `prometheus_subsystem`, but instead of `.` we use `_` delimiter to conform with Prometheus naming conventions + append the unit
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco", {{"example_key1", "example1"},{"example_key2", "example2"}});
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images",example_key1="example1",example_key2="example2"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
			// Test only one const_labels
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco", {{"example_key1", "example1"}});
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images",example_key1="example1"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
			// Test no const_labels
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco");
			prometheus_text_substring = R"(# HELP testns_falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_missing_container_images_total gauge
testns_falco_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
			// Test no prometheus_subsytem
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns");
			prometheus_text_substring = R"(# HELP testns_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE testns_n_missing_container_images_total gauge
testns_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
			// Test no prometheus_namespace
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric);
			prometheus_text_substring = R"(# HELP n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE n_missing_container_images_total gauge
n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
			//  Test no prometheus_namespace, but prometheus_subsytem
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "", "falco");
			prometheus_text_substring = R"(# HELP falco_n_missing_container_images_total https://falco.org/docs/metrics/
# TYPE falco_n_missing_container_images_total gauge
falco_n_missing_container_images_total{raw_name="n_missing_container_images"} 0
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "memory_rss_bytes", strlen(metric.name)) == 0)
		{
			// Test that libs native metric unit suffix was removed and replaced by the Prometheus specific unit suffix naming convention
			// todo adjust once base units are implemented
			prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco");
			prometheus_text_substring = R"(# HELP testns_falco_memory_rss_bytes https://falco.org/docs/metrics/
# TYPE testns_falco_memory_rss_bytes gauge
testns_falco_memory_rss_bytes{raw_name="memory_rss_bytes"} )";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		}
	}

	ASSERT_EQ(metrics_names_all_str_post_unit_conversion_pre_prometheus_text_conversion, 
	"cpu_usage_ratio memory_rss_bytes memory_vsz_bytes memory_pss_bytes container_memory_used_bytes host_cpu_usage_ratio host_procs_running host_memory_used_bytes host_open_fds n_threads n_fds n_noncached_fd_lookups n_cached_fd_lookups n_failed_fd_lookups n_added_fds n_removed_fds n_stored_evts n_store_evts_drops n_retrieved_evts n_retrieve_evts_drops n_noncached_thread_lookups n_cached_thread_lookups n_failed_thread_lookups n_added_threads n_removed_threads n_drops_full_threadtable n_missing_container_images n_containers");

	// Test global wrapper base metrics (pseudo metrics)
	prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus("kernel_release", "testns", "falco", {{"kernel_release", "6.6.7-200.fc39.x86_64"}});
	prometheus_text_substring = R"(# HELP testns_falco_kernel_release_info https://falco.org/docs/metrics/
# TYPE testns_falco_kernel_release_info gauge
testns_falco_kernel_release_info{raw_name="kernel_release",kernel_release="6.6.7-200.fc39.x86_64"} 1
)";
	std::cerr << prometheus_text;
	ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;

	// Another round of fake metric tests since we do not fetch real scap metrics, for example.
	std::vector<metrics_v2> fake_metrics_snapshot;
	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("sys_enter.run_cnt",
											METRICS_V2_LIBBPF_STATS, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_COUNT, 
											METRIC_VALUE_METRIC_TYPE_MONOTONIC, 
											76435525241UL));

	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("sys_enter.run_time_ns",
											METRICS_V2_LIBBPF_STATS, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_NS_COUNT, 
											METRIC_VALUE_METRIC_TYPE_MONOTONIC, 
											16269369826392UL));

	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("sys_enter.avg_time_ns",
											METRICS_V2_LIBBPF_STATS, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_NS, 
											METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT, 
											203UL));

	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("n_drops",
											METRICS_V2_KERNEL_COUNTERS, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_COUNT, 
											METRIC_VALUE_METRIC_TYPE_MONOTONIC, 
											674200UL));

	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("n_drops_buffer_total",
											METRICS_V2_KERNEL_COUNTERS, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_COUNT, 
											METRIC_VALUE_METRIC_TYPE_MONOTONIC, 
											5000UL));

	// Simulate some derived metrics; critical for example for Falco consumer use cases
	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("duration_sec",
											METRICS_V2_MISC,
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_S_COUNT, 
											METRIC_VALUE_METRIC_TYPE_MONOTONIC, 
											144UL));

	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("evt_rate_sec",
											METRICS_V2_MISC,
											METRIC_VALUE_TYPE_D,
											METRIC_VALUE_UNIT_TIME_S, 
											METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT, 
											126065.4));

	// Timestamps while they always go up should still be regarded as gauge from a Prometheus perspective
	// https://www.robustperception.io/are-increasing-timestamps-counters-or-gauges/
	fake_metrics_snapshot.emplace_back(libs_metrics_collector.new_metric("host_boot_ts",
											METRICS_V2_MISC, 
											METRIC_VALUE_TYPE_U64,
											METRIC_VALUE_UNIT_TIME_TIMESTAMP_NS, 
											METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT, 
											1708753667000000000UL));

	for (auto& metric: fake_metrics_snapshot)
	{
		prometheus_metrics_converter.convert_metric_to_unit_convention(metric);
		prometheus_text = prometheus_metrics_converter.convert_metric_to_text_prometheus(metric, "testns", "falco");
		std::cerr << prometheus_text;
		if (strncmp(metric.name, "sys_enter.run_cnt", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_sys_enter_run_cnt_total https://falco.org/docs/metrics/
# TYPE testns_falco_sys_enter_run_cnt_total counter
testns_falco_sys_enter_run_cnt_total{raw_name="sys_enter.run_cnt"} 76435525241
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "sys_enter.run_time_ns", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_sys_enter_run_time_nanoseconds_total https://falco.org/docs/metrics/
# TYPE testns_falco_sys_enter_run_time_nanoseconds_total counter
testns_falco_sys_enter_run_time_nanoseconds_total{raw_name="sys_enter.run_time_ns"} 16269369826392
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "sys_enter.avg_time_ns", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_sys_enter_avg_time_nanoseconds https://falco.org/docs/metrics/
# TYPE testns_falco_sys_enter_avg_time_nanoseconds gauge
testns_falco_sys_enter_avg_time_nanoseconds{raw_name="sys_enter.avg_time_ns"} 203
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "n_drops_buffer_total", strlen(metric.name)) == 0 && strlen(metric.name) == 20) // avoid clash with "n_drops" metric name
		{
			prometheus_text_substring = R"(# HELP testns_falco_n_drops_buffer_total https://falco.org/docs/metrics/
# TYPE testns_falco_n_drops_buffer_total counter
testns_falco_n_drops_buffer_total{raw_name="n_drops_buffer_total"} 5000
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "duration_sec", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_duration_seconds_total https://falco.org/docs/metrics/
# TYPE testns_falco_duration_seconds_total counter
testns_falco_duration_seconds_total{raw_name="duration_sec"} 144
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "evt_rate_sec", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_evt_rate_seconds https://falco.org/docs/metrics/
# TYPE testns_falco_evt_rate_seconds gauge
testns_falco_evt_rate_seconds{raw_name="evt_rate_sec"} 126065.400000
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		} else if (strncmp(metric.name, "host_boot_ts", strlen(metric.name)) == 0)
		{
			prometheus_text_substring = R"(# HELP testns_falco_host_boot_timestamp_nanoseconds https://falco.org/docs/metrics/
# TYPE testns_falco_host_boot_timestamp_nanoseconds gauge
testns_falco_host_boot_timestamp_nanoseconds{raw_name="host_boot_ts"} 1708753667000000000
)";
			ASSERT_TRUE(prometheus_text.find(prometheus_text_substring) != std::string::npos) << "Substring not found in prometheus_text got\n" << prometheus_text;
		}
	}

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
	libs::metrics::libs_metrics_collector libs_metrics_collector(&m_inspector, test_metrics_flags);
	libs::metrics::output_rule_metrics_converter output_rule_metrics_converter;

	/* Multiple calls */
	libs_metrics_collector.snapshot();
	auto metrics_snapshot = libs_metrics_collector.get_metrics();
	libs_metrics_collector.snapshot();
	libs_metrics_collector.snapshot();
	metrics_snapshot = libs_metrics_collector.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 28);

	/* These names should always be available, note that we currently can't check for the merged scap stats metrics here */
	std::unordered_set<std::string> minimal_metrics_names = {"cpu_usage_perc", "memory_rss_kb", "host_open_fds", \
	"n_threads", "n_fds", "n_added_fds", "n_added_threads", "n_removed_threads", "n_containers"};

	for(const auto& metric_name : minimal_metrics_names)
	{
		size_t i = 0;
		for (const auto& metric: metrics_snapshot) 
		{
			if(metric_name == metric.name)
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
	int success_memory_cnt = 0;
	int success_values_cnt = 0;
	for (auto& metric: metrics_snapshot)
	{
		// This resembles the Falco client use case and would be called if `convert_memory_to_mb` is set to true
		output_rule_metrics_converter.convert_metric_to_unit_convention(metric);
		if (std::find(metrics_names_memory.begin(), metrics_names_memory.end(), metric.name) != metrics_names_memory.end())
		{
			ASSERT_EQ(metric.unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES);
			ASSERT_EQ(metric.type, METRIC_VALUE_TYPE_D);
			if (strncmp(metric.name, "host_memory_used_mb", strlen(metric.name)) == 0 || strncmp(metric.name, "memory_rss_mb", strlen(metric.name)) == 0)
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
	libs::metrics::libs_metrics_collector libs_metrics_collector2(&m_inspector, 0);
	libs_metrics_collector2.snapshot();
	metrics_snapshot = libs_metrics_collector2.get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Sanity check empty inspector */
	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	libs::metrics::libs_metrics_collector libs_metrics_collector3(nullptr, test_metrics_flags);
	libs_metrics_collector3.snapshot();
	metrics_snapshot = libs_metrics_collector3.get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	/* Some sanity checks for selective flags */
	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_KERNEL_COUNTERS; // 20, but can't test it here it's 0
	test_metrics_flags |= METRICS_V2_LIBBPF_STATS; // 21 (x86_64 machine), but can't test it here it's 0
	libs::metrics::libs_metrics_collector libs_metrics_collector4(&m_inspector, test_metrics_flags);
	libs_metrics_collector4.snapshot();
	metrics_snapshot = libs_metrics_collector4.get_metrics();
	ASSERT_TRUE(metrics_snapshot.empty());

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_RESOURCE_UTILIZATION;
	libs::metrics::libs_metrics_collector libs_metrics_collector5(&m_inspector, test_metrics_flags);
	libs_metrics_collector5.snapshot();
	metrics_snapshot = libs_metrics_collector5.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 9);

	test_metrics_flags = 0;
	test_metrics_flags |= METRICS_V2_STATE_COUNTERS;
	libs::metrics::libs_metrics_collector libs_metrics_collector6(&m_inspector, test_metrics_flags);
	libs_metrics_collector6.snapshot();
	metrics_snapshot = libs_metrics_collector6.get_metrics();
	ASSERT_EQ(metrics_snapshot.size(), 19);

	test_metrics_flags = (METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS);
	libs::metrics::libs_metrics_collector libs_metrics_collector7(&m_inspector, test_metrics_flags);
	libs_metrics_collector7.snapshot();
	metrics_snapshot = libs_metrics_collector7.get_metrics();
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
