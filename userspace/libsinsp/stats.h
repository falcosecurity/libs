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
namespace stats {

	/*!
	  \brief Retrieve current sinsp stats v2 including resource utilization metrics.
	  \param agent_info Pointer to a \ref scap_agent_info containing relevant constants from the agent start up moment.
	  \param thread_manager Pointer to a \ref thread_manager to access threadtable properties.
	  \param stats_v2 Pointer to a \ref sinsp_stats_v2 containing counters related to the sinsp state tables (e.g. adding, removing, storing, failed lookup activities).
	  \param buffer Pointer to a \ref scap_stats_v2 pre-allocated sinsp_stats_v2_buffer (aka scap_stats_v2 schema).
	  \param nstats Pointer reflecting number of statistics in returned buffer
	  \param rc Pointer to return code
	  \note Intended to be called once every x hours.

	  \return Pointer to a \ref scap_stats_v2 buffer filled with the current sinsp stats v2 including resource utilization metrics.
	*/
	const scap_stats_v2* get_sinsp_stats_v2(uint32_t flags, const scap_agent_info* agent_info, sinsp_thread_manager* thread_manager, std::shared_ptr<sinsp_stats_v2> stats_v2, scap_stats_v2* buffer, uint32_t* nstats, int32_t* rc);

}
}
#endif
