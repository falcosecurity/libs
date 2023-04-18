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

#include "utils.h"

typedef enum sinsp_resource_utilization_stats {
	SINSP_RESOURCE_UTILIZATION_CPU_PERC = 0, ///< Current CPU usage, `ps` like, unit: percentage of one CPU.
	SINSP_RESOURCE_UTILIZATION_MEMORY_RSS, ///< Current RSS (Resident Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ, ///< Current VSZ (Virtual Memory Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_MEMORY_PSS, ///< Current PSS (Proportional Set Size), unit: kb.
	SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY, ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: bytes.
	SINSP_MAX_RESOURCE_UTILIZATION
}sinsp_resource_utilization_stats;

namespace libsinsp {
namespace resource_utilization {

	/*!
	  \brief Retrieve current resource utilization metrics.
	  \param agent_info Pointer to a \ref scap_agent_info containing relevant constants from the agent start up moment.
	  \param stats Pointer to a \ref scap_stats_v2 pre-allocated sinsp stats v2 buffer w/ scap_stats_v2 schema.
	  \param nstats Pointer reflecting number of statistics in returned buffer
	  \param rc Pointer to return code
	  \note Intended to be called once every x hours.

	  \return Pointer to a \ref scap_stats_v2 buffer filled with the current resource utilization metrics
	*/
	const scap_stats_v2* get_resource_utilization(const scap_agent_info* agent_info, scap_stats_v2* stats, uint32_t* nstats, int32_t* rc);

}
}
