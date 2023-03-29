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

#include <sys/times.h>
#include <sys/stat.h>
#include "utils.h"

typedef struct sinsp_resource_utilization
{
	double cpu_usage_perc; ///< Current CPU usage, `ps` like, unit: percentage of one CPU.
	uint32_t memory_rss; ///< Current RSS (Resident Set Size), unit: MB.
	uint32_t memory_vsz; ///< Current VSZ (Virtual Memory Size), unit: MB.
	uint32_t memory_pss; ///< Current PSS (Proportional Set Size), unit: MB.
	uint32_t container_memory_used; ///< Cgroup current memory used, default Kubernetes /sys/fs/cgroup/memory/memory.usage_in_bytes, unit: MB.
}sinsp_resource_utilization;

namespace libsinsp {
namespace resource_utilization {

	/*!
	  \brief Retrieve current CPU usage snapshot via a ps like approach.
	  Unit: percentage of one CPU.
	  \note Intended to be called once every x hours.
	*/
	void get_cpu_usage(double &cpu_usage_perc, const scap_agent_info* agent_info);

	/*!
	  \brief Retrieve current standard memory usage snapshot via a proc file approach.
	  Unit: MB. Precision loss because of division on UINT32 by design when converting from kb to MB.
	  \note Intended to be called once every x hours.
	*/
	void get_rss_vsz_pss_memory(uint32_t &rss, uint32_t &vsz, uint32_t &pss);

	/*!
	  \brief Retrieve current container_memory_usage snapshot via a proc file approach.
	  Unit: MB. Precision loss because of division on UINT32 by design when converting from bytes to MB.
	  \note Defaults to Kubernetes / "cloud-native" standard cgroup path. Intended to be called once every x hours.
	*/
	void get_container_memory_usage(uint32_t &memory_used);

	/*!
	  \brief Retrieve current resource_utilization snapshot via filling utilization struct.
	  \note Intended to be called once every x hours.
	*/
	void get_resource_utilization_snapshot(sinsp_resource_utilization* utilization, const scap_agent_info* agent_info);

}
}


