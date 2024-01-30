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

#pragma once

#include <libscap/metrics_v2.h>
#include <libscap/scap_machine_info.h>
#include <libsinsp/threadinfo.h>
#include <libscap/strl.h>
#include <cmath>

struct sinsp_stats_v2
{
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_failed_fd_lookups;
	uint64_t m_n_added_fds;
	uint64_t m_n_removed_fds;
	uint64_t m_n_stored_evts;
	uint64_t m_n_store_evts_drops;
	uint64_t m_n_retrieved_evts;
	uint64_t m_n_retrieve_evts_drops;
	uint64_t m_n_noncached_thread_lookups;
	uint64_t m_n_cached_thread_lookups;
	uint64_t m_n_failed_thread_lookups;
	uint64_t m_n_added_threads;
	uint64_t m_n_removed_threads;
	uint32_t m_n_drops_full_threadtable;
	uint32_t m_n_missing_container_images;
	uint32_t m_n_containers;
};

enum sinsp_stats_v2_resource_utilization
{
	SINSP_RESOURCE_UTILIZATION_CPU_PERC = 0, ///< Current CPU usage, `ps` util like calculation for the calling process (/proc/self), unit: percentage of one CPU.
	SINSP_RESOURCE_UTILIZATION_MEMORY_RSS, ///< Current RSS (Resident Set Size), calculated based on /proc/self/status info, unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ, ///< Current VSZ (Virtual Memory Size), calculated based on /proc/self/status info, unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_PSS, ///< Current PSS (Proportional Set Size), calculated based on /proc/self/smaps_rollup info, unit: kb.
	SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY, ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: bytes.
	SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST, ///< Current total host CPU usage (all CPUs), calculated based on ${HOST_ROOT}/proc/stat info, unit: percentage.
	SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST, ///< Current total memory used out of available host memory, calculated based on ${HOST_ROOT}/proc/meminfo info, unit: kb.
	SINSP_RESOURCE_UTILIZATION_PROCS_HOST, ///< Number of processes currently running on CPUs on the host, retrieved from ${HOST_ROOT}/proc/stat line `procs_running`, unit: count.
	SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST, ///< Number of allocated fds on the host, retrieved from ${HOST_ROOT}/proc/sys/fs/file-nr, unit: count.
	SINSP_STATS_V2_N_THREADS, ///< Total number of threads currently stored in the sinsp state thread table, unit: count.
	SINSP_STATS_V2_N_FDS, ///< Total number of fds currently stored across all threadtables associated with each active thread in the sinsp state thread table, unit: count.
	SINSP_STATS_V2_NONCACHED_FD_LOOKUPS, ///< fdtable state related counters, unit: count.
	SINSP_STATS_V2_CACHED_FD_LOOKUPS, ///< fdtable state related counters, unit: count.
	SINSP_STATS_V2_FAILED_FD_LOOKUPS, ///< fdtable state related counters, unit: count.
	SINSP_STATS_V2_ADDED_FDS, ///< fdtable state related counters, unit: count.
	SINSP_STATS_V2_REMOVED_FDS, ///< fdtable state related counters, unit: count.
	SINSP_STATS_V2_STORED_EVTS, ///< evt parsing related counters, unit: count.
	SINSP_STATS_V2_STORE_EVTS_DROPS, ///< evt parsing related counters, unit: count.
	SINSP_STATS_V2_RETRIEVED_EVTS, ///< evt parsing related counters, unit: count.
	SINSP_STATS_V2_RETRIEVE_EVTS_DROPS, ///< evt parsing related counters, unit: count.
	SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS, ///< threadtable state related counters, unit: count.
	SINSP_STATS_V2_CACHED_THREAD_LOOKUPS, ///< threadtable state related counters, unit: count.
	SINSP_STATS_V2_FAILED_THREAD_LOOKUPS, ///< threadtable state related counters, unit: count.
	SINSP_STATS_V2_ADDED_THREADS, ///< threadtable state related counters, unit: count.
	SINSP_STATS_V2_REMOVED_THREADS, ///< threadtable state related counters, unit: count.
	SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE, ///< Number of drops due to full threadtable, unit: count.
	SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES, ///<  Number of cached containers (cgroups) without container info such as image, hijacked sinsp_container_manager::remove_inactive_containers() -> every flush snapshot update, unit: count.
	SINSP_STATS_V2_N_CONTAINERS, ///<  Number of containers (cgroups) currently cached by sinsp_container_manager, hijacked sinsp_container_manager::remove_inactive_containers() -> every flush snapshot update, unit: count.
	SINSP_MAX_STATS_V2
};

#ifdef __linux__

namespace libsinsp::metrics {

class metrics_collector
{
public:
	metrics_collector(sinsp* inspector, uint32_t flags, bool convert_memory_to_mb);

	/*!
	\brief Method to fill up m_metrics_buffer with metrics; refreshes m_metrics with up-to-date metrics on each call
	*/
	void snapshot();

	/*!
	\brief Method to get a const reference to m_metrics vector
	*/
	const std::vector<metrics_v2>& get_metrics() const;

	/*!
	\brief Method to convert a metric to the text-based Prometheus format.
	 * Reference: https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
	 * Note: The design idea is to expose Prometheus metrics by piping text-based formats to new line-delimited fields 
	 * exposed at /metrics in Falco or a similar approach, eliminating the need for implementing a full Prometheus client.
	 * Example:
	 * test.memory_used_host{raw_name="memory_used_host", unit="MEMORY_MEGABYTES", metric_type="NON_MONOTONIC_CURRENT"} 15096.000000 1706490801547502000
	 * 
	 * This method is a work in progress.
	*/
	std::string convert_metric_to_prometheus_text(std::string metric_name, metrics_v2 metric);

	/*!
	\brief Method to convert memory units; tied to metrics_v2 definitions
	*/
	template <typename T>
	static double convert_memory(metrics_v2_value_unit source_unit, metrics_v2_value_unit dest_unit, T val)
	{
		double factor = 1;
		switch(source_unit)
		{
		case METRIC_VALUE_UNIT_MEMORY_BYTES:
			factor = 1;
			break;
		case METRIC_VALUE_UNIT_MEMORY_KILOBYTES:
			factor = 1024.;
			break;
		case METRIC_VALUE_UNIT_MEMORY_MEGABYTES:
			factor = 1024. * 1024.;
			break;
		default:
			return 0;
		}

		double bytes_val = val * factor;
		switch(dest_unit)
		{
		case METRIC_VALUE_UNIT_MEMORY_BYTES:
			return bytes_val;
		case METRIC_VALUE_UNIT_MEMORY_KILOBYTES:
			return std::round((bytes_val / 1024.) * 10.) / 10.; // round to 1 decimal
		case METRIC_VALUE_UNIT_MEMORY_MEGABYTES:
			return std::round((bytes_val / 1024. / 1024.) * 10.) / 10.; // round to 1 decimal
		default:
			return 0;
		}
		return 0;
	}

private:
	sinsp* m_inspector;
	uint32_t m_metrics_flags = METRICS_V2_KERNEL_COUNTERS | METRICS_V2_LIBBPF_STATS | METRICS_V2_RESOURCE_UTILIZATION | METRICS_V2_STATE_COUNTERS;
	bool m_convert_memory_to_mb = true;
	std::vector<metrics_v2> m_metrics;

	void get_rss_vsz_pss_total_memory_and_open_fds(uint32_t &rss, uint32_t &vsz, uint32_t &pss, uint64_t &memory_used_host, uint64_t &open_fds_host);
	void get_cpu_usage_and_total_procs(double start_time, double &cpu_usage_perc, double &cpu_usage_perc_total_host, uint32_t &procs_running_host);
	uint64_t get_container_memory_usage() const;

	template <typename T>
	const metrics_v2 new_metric(const char* name, uint32_t flags, metrics_v2_value_type type, metrics_v2_value_unit unit, metrics_v2_metric_type metric_type, T val)
	{
		metrics_v2 metric;
		strlcpy(metric.name, name, METRIC_NAME_MAX);
		metric.flags = flags;
		metric.type = type;
		metric.unit = unit;
		metric.metric_type = metric_type;
		set_new_metric(metric, type, val);
		return metric;
	}

	template <typename T>
	static void set_new_metric(metrics_v2& metric, metrics_v2_value_type type, T val)
	{
		switch (type)
		{
		case METRIC_VALUE_TYPE_U32:
			metric.value.u32 = static_cast<uint32_t>(val);
			break;
		case METRIC_VALUE_TYPE_S32:
			metric.value.s32 = static_cast<int32_t>(val);
			break;
		case METRIC_VALUE_TYPE_U64:
			metric.value.u64 = static_cast<uint64_t>(val);
			break;
		case METRIC_VALUE_TYPE_S64:
			metric.value.s64 = static_cast<int64_t>(val);
			break;
		case METRIC_VALUE_TYPE_D:
			metric.value.d = static_cast<double>(val);
			break;
		case METRIC_VALUE_TYPE_F:
			metric.value.f = static_cast<float>(val);
			break;
		case METRIC_VALUE_TYPE_I:
			metric.value.i = static_cast<int>(val);
			break;
		default:
			break;
		}
	}
};

} // namespace libsinsp::metrics

#endif
