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
#include <sys/sysinfo.h>


struct sinsp_resource_utilization;

void libsinsp::resource_utilization::get_rss_vsz_pss_memory(uint32_t &rss, uint32_t &vsz, uint32_t &pss)
{
	char filename[1024];
	char line[512];
	pid_t pid = getpid();

	snprintf(filename, sizeof(filename), "/proc/%d/status", pid);
	if(FILE* f = fopen(filename, "r"))
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			if(strstr(line, "VmSize:") == line)
			{
				sscanf(line, "VmSize: %u", &vsz);		/* memory size returned in kb */
				vsz /= 1024;		/* convert to MB with precision loss by design */
			} else if(strstr(line, "VmRSS:") == line)
			{
				sscanf(line, "VmRSS: %u", &rss);		/* memory size returned in kb */
				rss /= 1024;		/* convert to MB with precision loss by design */
			}
		}
		fclose(f);
	}

    snprintf(filename, sizeof(filename), "/proc/%d/smaps_rollup", pid);
	if(FILE* f = fopen(filename, "r"))
	{
		while(fgets(line, sizeof(line), f) != NULL)
		{
			if(strstr(line, "Pss:") == line)
			{
				sscanf(line, "Pss: %u", &pss);		/* memory size returned in kb */
				pss /= 1024;		/* convert to MB with precision loss by design */
				break;
			}
		}
		fclose(f);
	}
}

void libsinsp::resource_utilization::get_cpu_usage(double &cpu_usage_perc, const scap_agent_info* agent_info)
{

	struct tms time;
	if (times (&time) != (clock_t) -1)
	{

		/* Number of clock ticks per second, often referred to as USER_HZ / jiffies. */
		long hz = 100;
#ifdef _SC_CLK_TCK
		if ((hz = sysconf(_SC_CLK_TCK)) < 0)
		{
			ASSERT(false);
		}
#endif
		struct sysinfo s_info;
		if(sysinfo(&s_info) != 0)
		{
			ASSERT(false);
		}

		/* Current utime is amount of processor time in user mode of calling process.
		 * Convert to seconds. */
		double user_sec = (double)time.tms_utime / hz;

		/* Current stime is amount of time the calling process has been scheduled in kernel mode.
		 * Convert to seconds. */
		double system_sec = (double)time.tms_stime / hz;

		/* Current uptime of the host machine from sysinfo in seconds. */
		long machine_uptime_sec = s_info.uptime;

		/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
		 * currently elapsed time of the calling process. Compare to `ps` linux util. */
		double elapsed_sec = machine_uptime_sec - agent_info->start_time;
		cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
		cpu_usage_perc = std::round(cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal
	}
}

void libsinsp::resource_utilization::get_container_memory_usage(uint32_t &memory_used)
{
	/* In Kubernetes `container_memory_working_set_bytes` is the memory measure the OOM killer uses
	 * and values from `/sys/fs/cgroup/memory/memory.usage_in_bytes` are close enough.
	 * -> contrasted numbers from multiple sources in a real-life Kubernetes cluster.
	 *
	 * Please note that `kubectl top pod` numbers would reflect the sum of containers in a pod and
	 * typically libs clients (e.g. Falco) pods contain sidekick containers that use memory as well.
	 * This metric accounts only for the container with the security monitoring agent running.
	*/
	char filename[1024];
	const char *env_filename = getenv(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR);
	if(env_filename != NULL)
	{
		snprintf(filename, sizeof(filename), "%s", env_filename);
	}
	else
	{
		snprintf(filename, sizeof(filename), "%s", "/sys/fs/cgroup/memory/memory.usage_in_bytes");
	}

	if(FILE* f = fopen(filename, "r"))
	{
		uint64_t tmp_memory_used = 0;
		fscanf(f, "%lu", &tmp_memory_used);		/* memory size returned in bytes */
		memory_used = (uint32_t)(tmp_memory_used / 1024 / 1024);		/* convert to MB with precision loss by design */
		fclose(f);
	}
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

