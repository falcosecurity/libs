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
