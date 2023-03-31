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

typedef struct sinsp_resource_utilization
{
	double cpu_usage_perc; ///< Current CPU usage, `ps` like, unit: percentage of one CPU.
	uint32_t memory_rss; ///< Current RSS (Resident Set Size), unit: kb.
	uint32_t memory_vsz; ///< Current VSZ (Virtual Memory Size), unit: kb.
	uint32_t memory_pss; ///< Current PSS (Proportional Set Size), unit: kb.
	uint64_t container_memory_used; ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: bytes.
}sinsp_resource_utilization;

namespace libsinsp {
namespace resource_utilization {

	/*!
	  \brief Retrieve current resource_utilization snapshot.
	  \param scap_agent_info pointer containing relevant constants from the agent start up moment.
	  \note Intended to be called once every x hours.

	  \return sinsp_resource_utilization pointer.
	*/
	sinsp_resource_utilization* get_resource_utilization_snapshot(const scap_agent_info* agent_info);

	/*!
	  \brief Free sinsp_resource_utilization pointer.
	*/
	void free_resource_utilization_snapshot(sinsp_resource_utilization* utilization);

}
}
