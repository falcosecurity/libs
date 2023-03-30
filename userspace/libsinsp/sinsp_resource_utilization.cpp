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

#include <cmath>
#include "sinsp_resource_utilization.h"
#include <sys/times.h>
#include <sys/stat.h>
#include "utils.h"
#include <sinsp.h>
#include "sinsp_public.h"

struct sinsp_resource_utilization;

void libsinsp::resource_utilization::get_rss_vsz_pss_memory(uint32_t &rss, uint32_t &vsz, uint32_t &pss)
{
	char filepath[512];
	char line[512];
	pid_t pid = getpid();

	snprintf(filepath, sizeof(filepath), "/proc/%d/status", pid);
	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "VmSize:", 7) == 0)
		{
			sscanf(line, "VmSize: %u", &vsz);		/* memory size returned in kb */
		}
		else if(strncmp(line, "VmRSS:", 6) == 0)
		{
			sscanf(line, "VmRSS: %u", &rss);		/* memory size returned in kb */
		}
	}
	fclose(f);

    snprintf(filepath, sizeof(filepath), "/proc/%d/smaps_rollup", pid);
	f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "Pss:", 4) == 0)
		{
			sscanf(line, "Pss: %u", &pss);		/* memory size returned in kb */
			break;
		}
	}
	fclose(f);
}

void libsinsp::resource_utilization::get_cpu_usage(double &cpu_usage_perc, const scap_agent_info* agent_info)
{

	struct tms time;
	if (times (&time) == (clock_t) -1)
	{
		return;
	}

	/* Number of clock ticks per second, often referred to as USER_HZ / jiffies. */
	long hz = 100;
#ifdef _SC_CLK_TCK
	if ((hz = sysconf(_SC_CLK_TCK)) < 0)
	{
		ASSERT(false);
		hz = 100;
	}
#endif

	/* Current utime is amount of processor time in user mode of calling process. Convert to seconds. */
	double user_sec = (double)time.tms_utime / hz;

	/* Current stime is amount of time the calling process has been scheduled in kernel mode. Convert to seconds. */
	double system_sec = (double)time.tms_stime / hz;

	/* Current uptime of the host machine in seconds.
	 * Can't use sysconf as it is not portable (only Linux)
	 * plus /proc/uptime offers higher precision w/ 2 decimals.
	 */
	double machine_uptime_sec = 0;
	char filepath[512];
	snprintf(filepath, sizeof(filepath), "%s/proc/uptime", scap_get_host_root());
	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	fscanf(f, "%lf", &machine_uptime_sec);
	fclose(f);

	/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
	 * currently elapsed time of the calling process. Compare to `ps` linux util. */
	double elapsed_sec = machine_uptime_sec - agent_info->start_time;
	cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
	cpu_usage_perc = std::round(cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal

}

void libsinsp::resource_utilization::get_container_memory_usage(uint64_t &memory_used)
{
	/* In Kubernetes `container_memory_working_set_bytes` is the memory measure the OOM killer uses
	 * and values from `/sys/fs/cgroup/memory/memory.usage_in_bytes` are close enough.
	 * -> contrasted numbers from multiple sources in a real-life Kubernetes cluster.
	 *
	 * Please note that `kubectl top pod` numbers would reflect the sum of containers in a pod and
	 * typically libs clients (e.g. Falco) pods contain sidekick containers that use memory as well.
	 * This metric accounts only for the container with the security monitoring agent running.
	*/

	const char* filepath = getenv(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR);
	if (filepath == nullptr)
	{
		filepath = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
	}

	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	fscanf(f, "%lu", &memory_used);		/* memory size returned in bytes */
	fclose(f);
}

void libsinsp::resource_utilization::get_resource_utilization_snapshot(sinsp_resource_utilization* utilization, const scap_agent_info* agent_info)
{
	/* Init */
	utilization->cpu_usage_perc = 0.0;
	utilization->memory_rss = 0;
	utilization->memory_vsz = 0;
	utilization->memory_pss = 0;
	utilization->container_memory_used = 0;

	/* CPU usage snapshot, "ps" utility like approach. */
	libsinsp::resource_utilization::get_cpu_usage(utilization->cpu_usage_perc, agent_info);

	/* Memory usage snapshot, "cloud-native" support via container_memory_used. */
	libsinsp::resource_utilization::get_rss_vsz_pss_memory(utilization->memory_rss, utilization->memory_vsz, utilization->memory_pss);
	libsinsp::resource_utilization::get_container_memory_usage(utilization->container_memory_used);
}

