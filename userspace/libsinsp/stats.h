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
#include <scap_stats_v2.h>
#include <scap_machine_info.h>
#include "internal_metrics.h"

typedef enum sinsp_stats_v2 {
	SINSP_RESOURCE_UTILIZATION_CPU_PERC = 0, ///< Current CPU usage, `ps` like, unit: percentage of one CPU.
	SINSP_RESOURCE_UTILIZATION_MEMORY_RSS, ///< Current RSS (Resident Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ, ///< Current VSZ (Virtual Memory Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_PSS, ///< Current PSS (Proportional Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY, ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: bytes.
	SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST, ///< Current total host CPU usage (all CPUs), unit: percentage.
	SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST, ///< Current total memory used out of available host memory, unit: kb.
	SINSP_RESOURCE_UTILIZATION_PROCS_HOST, ///< Number of processes currently running on CPUs on the host, unit: count.
	SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST,  ///< Number of allocated fds on the host, unit: count.
	SINSP_MAX_STATS_V2
}sinsp_stats_v2;

namespace libsinsp {
namespace stats {

	/*!
	  \brief Retrieve current sinsp stats v2 including resource utilization metrics.
	  \param agent_info Pointer to a \ref scap_agent_info containing relevant constants from the agent start up moment.
	  \param stats Pointer to a \ref scap_stats_v2 pre-allocated sinsp stats v2 buffer w/ scap_stats_v2 schema.
	  \param nstats Pointer reflecting number of statistics in returned buffer
	  \param rc Pointer to return code
	  \note Intended to be called once every x hours.

	  \return Pointer to a \ref scap_stats_v2 buffer filled with the current sinsp stats v2 including resource utilization metrics.
	*/
	const scap_stats_v2* get_sinsp_stats_v2(uint32_t flags, const scap_agent_info* agent_info, scap_stats_v2* stats, uint32_t* nstats, int32_t* rc);

}
}

#ifdef GATHER_INTERNAL_STATS

//
// Processing stats class.
// Keeps a bunch of counters with key library performance metrics.
//
class SINSP_PUBLIC sinsp_stats : public internal_metrics::processor
{
public:
	void clear();
	void emit(FILE* f);
	internal_metrics::registry& get_metrics_registry()
	{
		return m_metrics_registry;
	}

	void process(internal_metrics::counter& metric);

	uint64_t m_n_seen_evts;
	uint64_t m_n_drops;
	uint64_t m_n_preemptions;
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_failed_fd_lookups;
	uint64_t m_n_threads;
	uint64_t m_n_fds;
	uint64_t m_n_added_fds;
	uint64_t m_n_removed_fds;
	uint64_t m_n_stored_evts;
	uint64_t m_n_store_drops;
	uint64_t m_n_retrieved_evts;
	uint64_t m_n_retrieve_drops;

private:
	internal_metrics::registry m_metrics_registry;
	FILE* m_output_target;
};

#endif // GATHER_INTERNAL_STATS
