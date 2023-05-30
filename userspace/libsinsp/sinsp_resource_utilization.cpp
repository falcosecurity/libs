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
#include <unistd.h>
#include <inttypes.h>
#include <sys/times.h>
#include <sys/stat.h>
#include "sinsp_resource_utilization.h"
#include "utils.h"
#include <sinsp.h>
#include "sinsp_public.h"
#include "strl.h"

void get_rss_vsz_pss_memory(uint32_t &rss, uint32_t &vsz, uint32_t &pss)
{
	char line[512];

	FILE* f = fopen("/proc/self/status", "r");
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

	f = fopen("/proc/self/smaps_rollup", "r");
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

double get_cpu_usage(double start_time)
{
	double cpu_usage_perc = 0.0;

	struct tms time;
	if (times (&time) == (clock_t) -1)
	{
		return 0;
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
	 * /proc/uptime offers higher precision w/ 2 decimals.
	 */
	double machine_uptime_sec = 0;
	char filepath[512];
	snprintf(filepath, sizeof(filepath), "%s/proc/uptime", scap_get_host_root());
	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return 0;
	}

	int matched = fscanf(f, "%lf", &machine_uptime_sec);
	fclose(f);

	if (matched != 1) {
		return 0;
	}

	/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
	 * currently elapsed time of the calling process. Compare to `ps` linux util. */
	double elapsed_sec = machine_uptime_sec - start_time;
	if (elapsed_sec > 0)
	{
		cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
		cpu_usage_perc = std::round(cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal
	}

	return cpu_usage_perc;
}

uint64_t get_container_memory_usage()
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
		return 0;
	}
	unsigned long long memory_used = 0;

	/* memory size returned in bytes */
	int fscanf_matched = fscanf(f, "%llu", &memory_used);
	fclose(f);

	if (fscanf_matched != 1) {
		return 0;
	}

	return memory_used;
}

const scap_stats_v2* libsinsp::resource_utilization::get_resource_utilization(const scap_agent_info* agent_info, scap_stats_v2* stats, uint32_t* nstats, int32_t* rc)
{
	if (!stats)
	{
		*nstats = 0;
		*rc = SCAP_FAILURE;
		return NULL;
	}

	stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].type = STATS_VALUE_TYPE_D;
	stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].value.d = get_cpu_usage(agent_info->start_time);
	strlcpy(stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].name, "cpu_usage_perc", STATS_NAME_MAX);

	uint32_t rss = 0;
	uint32_t vsz = 0;
	uint32_t pss = 0;
	get_rss_vsz_pss_memory(rss, vsz, pss);
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].type = STATS_VALUE_TYPE_U32;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].value.u32 = rss;
	strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].name, "memory_rss", STATS_NAME_MAX);

	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].type = STATS_VALUE_TYPE_U32;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].value.u32 = vsz;
	strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].name, "memory_vsz", STATS_NAME_MAX);

	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].type = STATS_VALUE_TYPE_U32;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].value.u32 = pss;
	strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].name, "memory_pss", STATS_NAME_MAX);

	stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].type = STATS_VALUE_TYPE_U64;
	stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
	stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].value.u64 = get_container_memory_usage();
	strlcpy(stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].name, "container_memory_used", STATS_NAME_MAX);

	*nstats = SINSP_MAX_RESOURCE_UTILIZATION;
	*rc = SCAP_SUCCESS;

	return stats;
}
