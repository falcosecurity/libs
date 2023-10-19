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

////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_public.h"
#include <cmath>
#include <unistd.h>
#include <inttypes.h>
#include <sys/times.h>
#include <sys/stat.h>
#include "stats.h"
#include "strl.h"

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

	unsigned long long mem_total, mem_free, mem_buff, mem_cache = 0;

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "MemTotal:", 9) == 0)
		{
			sscanf(line, "MemTotal: %llu", &mem_total);		/* memory size returned in kb */
		}
		else if(strncmp(line, "MemFree:", 8) == 0)
		{
			sscanf(line, "MemFree: %llu", &mem_free);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Buffers:", 8) == 0)
		{
			sscanf(line, "Buffers: %llu", &mem_buff);		/* memory size returned in kb */
		}
		else if(strncmp(line, "Cached:", 7) == 0)
		{
			sscanf(line, "Cached: %llu", &mem_cache);		/* memory size returned in kb */
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
	int matched_fds = fscanf(f, "%llu", &open_fds_host);
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
	unsigned long long user, nice, system, idle, iowait, irq, softirq = 0;
	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strncmp(line, "cpu ", 4) == 0)
		{
			/* Always first line in /proc/stat file, unit: jiffies */
			sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait, &irq, &softirq);
		}
		else if(strncmp(line, "procs_running ", 14) == 0)
		{
			sscanf(line, "procs_running %u", &procs_running_host);
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

const scap_stats_v2* libsinsp::stats::get_sinsp_stats_v2(uint32_t flags, const scap_agent_info* agent_info, scap_stats_v2* stats, uint32_t* nstats, int32_t* rc)
{
	if (!stats)
	{
		*nstats = 0;
		*rc = SCAP_FAILURE;
		return NULL;
	}

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

		if(stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].name != nullptr && strncmp(stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].name, "cpu_usage_perc", 15) != 0)
		{
			// Init
			stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].type = STATS_VALUE_TYPE_D;
			stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].name, "cpu_usage_perc", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].type = STATS_VALUE_TYPE_U32;
			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].name, "memory_rss", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].type = STATS_VALUE_TYPE_U32;
			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].name, "memory_vsz", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].type = STATS_VALUE_TYPE_U32;
			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].name, "memory_pss", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].type = STATS_VALUE_TYPE_U64;
			stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].name, "container_memory_used", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].type = STATS_VALUE_TYPE_D;
			stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].name, "cpu_usage_perc_total_host", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].type = STATS_VALUE_TYPE_U32;
			stats[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].name, "procs_running_host", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].type = STATS_VALUE_TYPE_U64;
			stats[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].name, "memory_used_host", STATS_NAME_MAX);

			stats[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].type = STATS_VALUE_TYPE_U64;
			stats[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].flags = PPM_SCAP_STATS_RESOURCE_UTILIZATION;
			strlcpy(stats[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].name, "open_fds_host", STATS_NAME_MAX);
		} 

		// Get stats / metrics snapshot

		get_cpu_usage_and_total_procs(agent_info->start_time, cpu_usage_perc, cpu_usage_perc_total_host, procs_running_host);
		get_rss_vsz_pss_total_memory_and_open_fds(rss, vsz, pss, memory_used_host, open_fds_host);

		stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC].value.d = cpu_usage_perc;
		stats[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS].value.u32 = rss;
		stats[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ].value.u32 = vsz;
		stats[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS].value.u32 = pss;
		stats[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY].value.u64 = get_container_memory_usage();
		stats[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST].value.d = cpu_usage_perc_total_host;
		stats[SINSP_RESOURCE_UTILIZATION_PROCS_HOST].value.u32 = procs_running_host;
		stats[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST].value.u64 = memory_used_host;
		stats[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST].value.u64 = open_fds_host;

		*nstats = SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST + 1;

	}
	
	*rc = SCAP_SUCCESS;

	return stats;
}


#ifdef GATHER_INTERNAL_STATS

void sinsp_stats::clear()
{
	m_n_seen_evts = 0;
	m_n_drops = 0;
	m_n_preemptions = 0;
	m_n_noncached_fd_lookups = 0;
	m_n_cached_fd_lookups = 0;
	m_n_failed_fd_lookups = 0;
	m_n_threads = 0;
	m_n_fds = 0;
	m_n_added_fds = 0;
	m_n_removed_fds = 0;
	m_n_stored_evts = 0;
	m_n_store_drops = 0;
	m_n_retrieved_evts = 0;
	m_n_retrieve_drops = 0;
	m_metrics_registry.clear_all_metrics();
}

void sinsp_stats::emit(FILE* f)
{
	m_output_target = f;

	fprintf(f, "evts seen by driver: %" PRIu64 "\n", m_n_seen_evts);
	fprintf(f, "drops: %" PRIu64 "\n", m_n_drops);
	fprintf(f, "preemptions: %" PRIu64 "\n", m_n_preemptions);
	fprintf(f, "fd lookups: %" PRIu64 "(%" PRIu64 " cached %" PRIu64 " noncached)\n", 
		m_n_noncached_fd_lookups + m_n_cached_fd_lookups,
		m_n_cached_fd_lookups,
		m_n_noncached_fd_lookups);
	fprintf(f, "failed fd lookups: %" PRIu64 "\n", m_n_failed_fd_lookups);
	fprintf(f, "n. threads: %" PRIu64 "\n", m_n_threads);
	fprintf(f, "n. fds: %" PRIu64 "\n", m_n_fds);
	fprintf(f, "added fds: %" PRIu64 "\n", m_n_added_fds);
	fprintf(f, "removed fds: %" PRIu64 "\n", m_n_removed_fds);
	fprintf(f, "stored evts: %" PRIu64 "\n", m_n_stored_evts);
	fprintf(f, "store drops: %" PRIu64 "\n", m_n_store_drops);
	fprintf(f, "retrieved evts: %" PRIu64 "\n", m_n_retrieved_evts);
	fprintf(f, "retrieve drops: %" PRIu64 "\n", m_n_retrieve_drops);

	for(internal_metrics::registry::metric_map_iterator_t it = m_metrics_registry.get_metrics().begin(); it != m_metrics_registry.get_metrics().end(); it++)
	{
		fprintf(f, "%s: ", it->first.get_description().c_str());
		it->second->process(*this);
	}
}

void sinsp_stats::process(internal_metrics::counter& metric)
{
	fprintf(m_output_target, "%" PRIu64 "\n", metric.get_value());
}

#endif // GATHER_INTERNAL_STATS
