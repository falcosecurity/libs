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

#ifdef __linux__

#include <libsinsp/sinsp_int.h>
#include <cmath>
#include <sys/times.h>
#include <sys/stat.h>
#include <libsinsp/stats.h>
#include <libscap/strl.h>

static const char *const sinsp_stats_v2_resource_utilization_names[] = {
	[SINSP_RESOURCE_UTILIZATION_CPU_PERC] = "cpu_usage_perc",
	[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS] = "memory_rss",
	[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ] = "memory_vsz",
	[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS] = "memory_pss",
	[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY] = "container_memory_used",
	[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST] = "cpu_usage_perc_total_host",
	[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST] = "memory_used_host",
	[SINSP_RESOURCE_UTILIZATION_PROCS_HOST] = "procs_running_host",
	[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST] = "open_fds_host",
	[SINSP_STATS_V2_N_THREADS] = "n_threads",
	[SINSP_STATS_V2_N_FDS] = "n_fds",
	[SINSP_STATS_V2_NONCACHED_FD_LOOKUPS] = "n_noncached_fd_lookups",
	[SINSP_STATS_V2_CACHED_FD_LOOKUPS] = "n_cached_fd_lookups",
	[SINSP_STATS_V2_FAILED_FD_LOOKUPS] = "n_failed_fd_lookups",
	[SINSP_STATS_V2_ADDED_FDS] = "n_added_fds",
	[SINSP_STATS_V2_REMOVED_FDS] = "n_removed_fds",
	[SINSP_STATS_V2_STORED_EVTS] = "n_stored_evts",
	[SINSP_STATS_V2_STORE_EVTS_DROPS] = "n_store_evts_drops",
	[SINSP_STATS_V2_RETRIEVED_EVTS] = "n_retrieved_evts",
	[SINSP_STATS_V2_RETRIEVE_EVTS_DROPS] = "n_retrieve_evts_drops",
	[SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS] = "n_noncached_thread_lookups",
	[SINSP_STATS_V2_CACHED_THREAD_LOOKUPS] = "n_cached_thread_lookups",
	[SINSP_STATS_V2_FAILED_THREAD_LOOKUPS] = "n_failed_thread_lookups",
	[SINSP_STATS_V2_ADDED_THREADS] = "n_added_threads",
	[SINSP_STATS_V2_REMOVED_THREADS] = "n_removed_threads",
	[SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE] = "n_drops_full_threadtable",
	[SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES] = "n_missing_container_images",
	[SINSP_STATS_V2_N_CONTAINERS] = "n_containers",
};

void get_rss_vsz_pss_total_memory_and_open_fds(uint32_t &rss, uint32_t &vsz, uint32_t &pss, uint64_t &memory_used_host, uint64_t &open_fds_host)
{
	FILE* f;
	char filepath[512];
	char line[512];

	/*
	 * Get memory usage of the agent itself (referred to as calling process meaning /proc/self/)
	*/

	f = fopen("/proc/self/status", "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "VmSize:", 7) == 0)
		{
			sscanf(line, "VmSize: %" SCNu32, &vsz);		/* memory size returned in kb */
		}
		else if(strncmp(line, "VmRSS:", 6) == 0)
		{
			sscanf(line, "VmRSS: %" SCNu32, &rss);		/* memory size returned in kb */
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
			sscanf(line, "Pss: %" SCNu32, &pss);		/* memory size returned in kb */
			break;
		}
	}
	fclose(f);

	/*
	 * Get total host memory usage
	*/

	snprintf(filepath, sizeof(filepath), "%s/proc/meminfo", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	uint64_t mem_total, mem_free, mem_buff, mem_cache = 0;

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "MemTotal:", 9) == 0)
		{
			sscanf(line, "MemTotal: %" SCNu64, &mem_total);		/* memory size returned in kb */
		}
		else if(strncmp(line, "MemFree:", 8) == 0)
		{
			sscanf(line, "MemFree: %" SCNu64, &mem_free);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Buffers:", 8) == 0)
		{
			sscanf(line, "Buffers: %" SCNu64, &mem_buff);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Cached:", 7) == 0)
		{
			sscanf(line, "Cached: %" SCNu64, &mem_cache);		/* memory size returned in kb */
		}
	}
	fclose(f);
	memory_used_host = mem_total - mem_free - mem_buff - mem_cache;

	/*
	 * Get total number of allocated file descriptors (not all open files!)
	 * File descriptor is a data structure used by a program to get a handle on a file
	*/

	snprintf(filepath, sizeof(filepath), "%s/proc/sys/fs/file-nr", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}
	int matched_fds = fscanf(f, "%" SCNu64, &open_fds_host);
	fclose(f);

	if (matched_fds != 1) {
		ASSERT(false);
		return;
	}
}

void get_cpu_usage_and_total_procs(double start_time, double &cpu_usage_perc, double &cpu_usage_perc_total_host, uint32_t &procs_running_host)
{
	FILE* f;
	char filepath[512];
	char line[512];

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
	/* Current uptime of the host machine in seconds.
	 * /proc/uptime offers higher precision w/ 2 decimals.
	 */

	snprintf(filepath, sizeof(filepath), "%s/proc/uptime", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

	double machine_uptime_sec = 0;
	int matched_uptime = fscanf(f, "%lf", &machine_uptime_sec);
	fclose(f);

	if (matched_uptime != 1) {
		ASSERT(false);
		return;
	}

	/*
	 * Get CPU usage of the agent itself (referred to as calling process meaning /proc/self/)
	*/

	/* Current utime is amount of processor time in user mode of calling process. Convert to seconds. */
	double user_sec = (double)time.tms_utime / hz;

	/* Current stime is amount of time the calling process has been scheduled in kernel mode. Convert to seconds. */
	double system_sec = (double)time.tms_stime / hz;


	/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
	 * currently elapsed time of the calling process. Compare to `ps` linux util. */
	double elapsed_sec = machine_uptime_sec - start_time;
	if (elapsed_sec > 0)
	{
		cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
		cpu_usage_perc = std::round(cpu_usage_perc * 10.0) / 10.0; // round to 1 decimal
	}

	/*
	 * Get total host CPU usage (all CPUs) as percentage and retrieve number of procs currently running.
	*/

	snprintf(filepath, sizeof(filepath), "%s/proc/stat", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f)
	{
		ASSERT(false);
		return;
	}

    /* Need only first 7 columns of /proc/stat cpu line */
	uint64_t user, nice, system, idle, iowait, irq, softirq = 0;
	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "cpu ", 4) == 0)
		{
			/* Always first line in /proc/stat file, unit: jiffies */
			sscanf(line, "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64, &user, &nice, &system, &idle, &iowait, &irq, &softirq);
		}
		else if(strncmp(line, "procs_running ", 14) == 0)
		{
			sscanf(line, "procs_running %" SCNu32, &procs_running_host);
			break;
		}
	}
	fclose(f);
	auto sum = user + nice + system + idle + iowait + irq + softirq;
	if (sum > 0)
	{
		cpu_usage_perc_total_host = 100.0 - ((idle * 100.0) / sum);
		cpu_usage_perc_total_host = std::round(cpu_usage_perc_total_host * 10.0) / 10.0; // round to 1 decimal
	}
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
	uint64_t memory_used = 0;
	const char* filepath = getenv(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR);
	if (filepath == nullptr)
	{
		filepath = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
	}

	FILE* f = fopen(filepath, "r");
	if(!f)
	{
		return 0;
	}

	/* memory size returned in bytes */
	int fscanf_matched = fscanf(f, "%" SCNu64, &memory_used);
	fclose(f);

	if (fscanf_matched != 1) {
		return 0;
	}
	return memory_used;
}

const scap_stats_v2* libsinsp::stats::get_sinsp_stats_v2(uint32_t flags, const scap_agent_info* agent_info, sinsp_thread_manager* thread_manager, std::shared_ptr<sinsp_stats_v2> stats_v2, scap_stats_v2* buffer, uint32_t* nstats, int32_t* rc)
{
	if (!buffer)
	{
		*nstats = 0;
		*rc = SCAP_FAILURE;
		return NULL;
	}

	*nstats = 0;
	if((flags & PPM_SCAP_STATS_RESOURCE_UTILIZATION))
	{
		uint32_t rss = 0;
		uint32_t vsz = 0;
		uint32_t pss = 0;
		uint64_t memory_used_host = 0;
		uint64_t open_fds_host = 0;
		double cpu_usage_perc = 0.0;
		double cpu_usage_perc_total_host = 0.0;
		uint32_t procs_running_host = 0;

		if(strncmp(buffer[SINSP_RESOURCE_UTILIZATION_CPU_PERC].name, sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CPU_PERC], 15) != 0)
		{
			// Init
			for(uint32_t i = SINSP_RESOURCE_UTILIZATION_CPU_PERC; i < SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST + 1; i++)
			{
				buffer[i].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
				strlcpy(buffer[i].name, sinsp_stats_v2_resource_utilization_names[i], STATS_NAME_MAX);
			}

			buffer[SINSP_RESOURCE_UTILIZATION_CPU_PERC].type = STATS_VALUE_TYPE_D;
			buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].type = STATS_VALUE_TYPE_D;
			buffer[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].type = STATS_VALUE_TYPE_U64;
		}

		// Get stats / metrics snapshot

		get_cpu_usage_and_total_procs(agent_info->start_time, cpu_usage_perc, cpu_usage_perc_total_host, procs_running_host);
		get_rss_vsz_pss_total_memory_and_open_fds(rss, vsz, pss, memory_used_host, open_fds_host);

		buffer[SINSP_RESOURCE_UTILIZATION_CPU_PERC].value.d = cpu_usage_perc;
		buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].value.u32 = rss;
		buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].value.u32 = vsz;
		buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].value.u32 = pss;
		buffer[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].value.u64 = get_container_memory_usage();
		buffer[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].value.d = cpu_usage_perc_total_host;
		buffer[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].value.u32 = procs_running_host;
		buffer[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].value.u64 = memory_used_host;
		buffer[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].value.u64 = open_fds_host;

		*nstats = SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST + 1;

	}

	if((flags & PPM_SCAP_STATS_STATE_COUNTERS) && stats_v2)
	{
		if(strncmp(buffer[SINSP_STATS_V2_N_THREADS].name, sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_THREADS], 10) != 0)
		{
			// Init
			for(uint32_t i = SINSP_STATS_V2_N_THREADS; i < SINSP_MAX_STATS_V2; i++)
			{
				buffer[i].flags = PPM_SCAP_STATS_STATE_COUNTERS;
				strlcpy(buffer[i].name, sinsp_stats_v2_resource_utilization_names[i], STATS_NAME_MAX);
			}

			buffer[SINSP_STATS_V2_NONCACHED_FD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_CACHED_FD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_FAILED_FD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_ADDED_FDS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_REMOVED_FDS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_STORED_EVTS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_STORE_EVTS_DROPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_RETRIEVED_EVTS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_RETRIEVE_EVTS_DROPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_CACHED_THREAD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_FAILED_THREAD_LOOKUPS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_ADDED_THREADS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_REMOVED_THREADS].type = STATS_VALUE_TYPE_U64;
			buffer[SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES].type = STATS_VALUE_TYPE_U32;
			buffer[SINSP_STATS_V2_N_CONTAINERS].type = STATS_VALUE_TYPE_U32;

		}

		// Get stats / metrics snapshot

		buffer[SINSP_STATS_V2_N_THREADS].value.u64 = thread_manager->get_thread_count();
		buffer[SINSP_STATS_V2_N_FDS].value.u64 = 0;
		threadinfo_map_t* threadtable = thread_manager->get_threads();
		threadtable->loop([&] (sinsp_threadinfo& tinfo) {
			sinsp_fdtable* fdtable = tinfo.get_fd_table();
			if (fdtable != nullptr)
			{
				buffer[SINSP_STATS_V2_N_FDS].value.u64 += fdtable->size();
			}
			return true;
		});
		buffer[SINSP_STATS_V2_NONCACHED_FD_LOOKUPS].value.u64 = stats_v2->m_n_noncached_fd_lookups;
		buffer[SINSP_STATS_V2_CACHED_FD_LOOKUPS].value.u64 = stats_v2->m_n_cached_fd_lookups;
		buffer[SINSP_STATS_V2_FAILED_FD_LOOKUPS].value.u64 = stats_v2->m_n_failed_fd_lookups;
		buffer[SINSP_STATS_V2_ADDED_FDS].value.u64 = stats_v2->m_n_added_fds;
		buffer[SINSP_STATS_V2_REMOVED_FDS].value.u64 = stats_v2->m_n_removed_fds;
		buffer[SINSP_STATS_V2_STORED_EVTS].value.u64 = stats_v2->m_n_stored_evts;
		buffer[SINSP_STATS_V2_STORE_EVTS_DROPS].value.u64 = stats_v2->m_n_store_evts_drops;
		buffer[SINSP_STATS_V2_RETRIEVED_EVTS].value.u64 = stats_v2->m_n_retrieved_evts;
		buffer[SINSP_STATS_V2_RETRIEVE_EVTS_DROPS].value.u64 = stats_v2->m_n_retrieve_evts_drops;
		buffer[SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS].value.u64 = stats_v2->m_n_noncached_thread_lookups;
		buffer[SINSP_STATS_V2_CACHED_THREAD_LOOKUPS].value.u64 = stats_v2->m_n_cached_thread_lookups;
		buffer[SINSP_STATS_V2_FAILED_THREAD_LOOKUPS].value.u64 = stats_v2->m_n_failed_thread_lookups;
		buffer[SINSP_STATS_V2_ADDED_THREADS].value.u64 = stats_v2->m_n_added_threads;
		buffer[SINSP_STATS_V2_REMOVED_THREADS].value.u64 = stats_v2->m_n_removed_threads;
		buffer[SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE].value.u32 = stats_v2->m_n_drops_full_threadtable;
		buffer[SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES].value.u32 = stats_v2->m_n_missing_container_images;
		buffer[SINSP_STATS_V2_N_CONTAINERS].value.u32 = stats_v2->m_n_containers;

		*nstats = SINSP_MAX_STATS_V2;
	}

	*rc = SCAP_SUCCESS;
	return buffer;
}

#endif
