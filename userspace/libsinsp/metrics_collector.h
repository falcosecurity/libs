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
#include <libscap/scap_stats_v2.h>
#include <libscap/scap_machine_info.h>
#include <libsinsp/threadinfo.h>

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
	SINSP_RESOURCE_UTILIZATION_CPU_PERC = 0, ///< Current CPU usage, `ps` like, unit: percentage of one CPU.
	SINSP_RESOURCE_UTILIZATION_MEMORY_RSS, ///< Current RSS (Resident Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ, ///< Current VSZ (Virtual Memory Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_PSS, ///< Current PSS (Proportional Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY, ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: bytes.
	SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST, ///< Current total host CPU usage (all CPUs), unit: percentage.
	SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST, ///< Current total memory used out of available host memory, unit: kb.
	SINSP_RESOURCE_UTILIZATION_PROCS_HOST, ///< Number of processes currently running on CPUs on the host, unit: count.
	SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST, ///< Number of allocated fds on the host, unit: count.
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

namespace libsinsp {
namespace metrics {

class metrics_collector
{
public:
	// Factory method for creating instances
	static std::unique_ptr<metrics_collector> create(sinsp* inspector, const uint32_t flags);
	~metrics_collector();

	// Method to fill up m_metrics_buffer with current metrics; refreshes m_metrics with up-to-date metrics on each call
	void snapshot();

	// Method to get a const reference to m_metrics buffer
	const std::vector<scap_stats_v2>& get_metrics() const;

private:
	metrics_collector(sinsp* inspector, const uint32_t flags);
	static std::unique_ptr<metrics_collector> mc_instance;
	sinsp* m_inspector;
	uint32_t m_metrics_flags;
	std::vector<scap_stats_v2> m_metrics;

	void get_rss_vsz_pss_total_memory_and_open_fds(uint32_t &rss, uint32_t &vsz, uint32_t &pss, uint64_t &memory_used_host, uint64_t &open_fds_host);
	void get_cpu_usage_and_total_procs(double start_time, double &cpu_usage_perc, double &cpu_usage_perc_total_host, uint32_t &procs_running_host);
	uint64_t get_container_memory_usage() const;

	template <typename T>
	const scap_stats_v2 new_stat(const char* name, uint32_t flags, scap_stats_v2_value_type type, scap_stats_v2_value_unit unit, scap_stats_v2_metric_type metric_type, T val)
	{
		scap_stats_v2 stat;
		strlcpy(stat.name, name, STATS_NAME_MAX);
		stat.flags = flags;
		stat.type = type;
		stat.unit = unit;
		stat.metric_type = metric_type;
		set_stat_value(stat, type, val);
		return stat;
	}

	template <typename T>
	void set_stat_value(scap_stats_v2& stat, scap_stats_v2_value_type type, T val)
	{
		switch (type)
		{
		case STATS_VALUE_TYPE_U32:
			stat.type = STATS_VALUE_TYPE_U32;
			stat.value.u32 = static_cast<uint32_t>(val);
			break;
		case STATS_VALUE_TYPE_S32:
			stat.type = STATS_VALUE_TYPE_S32;
			stat.value.s32 = static_cast<int32_t>(val);
			break;
		case STATS_VALUE_TYPE_U64:
			stat.type = STATS_VALUE_TYPE_U64;
			stat.value.u64 = static_cast<uint64_t>(val);
			break;
		case STATS_VALUE_TYPE_S64:
			stat.type = STATS_VALUE_TYPE_S64;
			stat.value.s64 = static_cast<int64_t>(val);
			break;
		case STATS_VALUE_TYPE_D:
			stat.type = STATS_VALUE_TYPE_D;
			stat.value.d = static_cast<double>(val);
			break;
		case STATS_VALUE_TYPE_F:
			stat.type = STATS_VALUE_TYPE_F;
			stat.value.f = static_cast<float>(val);
			break;
		case STATS_VALUE_TYPE_I:
			stat.type = STATS_VALUE_TYPE_I;
			stat.value.i = static_cast<int>(val);
			break;
		default:
			break;
		}
	}
};

} // namespace metrics
} // namespace libsinsp

#endif
