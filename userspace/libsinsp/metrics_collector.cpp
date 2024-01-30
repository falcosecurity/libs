// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <libsinsp/metrics_collector.h>
#include <cmath>
#include <sys/times.h>
#include <sys/stat.h>

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

// For simplicity, needs to stay in sync w/ typedef enum metrics_v2_value_unit
static const char *const metrics_unit_name_mappings[] = {
	[METRIC_VALUE_UNIT_COUNT] = "COUNT",
	[METRIC_VALUE_UNIT_PERC] = "PERC",
	[METRIC_VALUE_UNIT_MEMORY_BYTES] = "MEMORY_BYTES",
	[METRIC_VALUE_UNIT_MEMORY_KILOBYTES] = "MEMORY_KILOBYTES",
	[METRIC_VALUE_UNIT_MEMORY_MEGABYTES] = "MEMORY_MEGABYTES",
	[METRIC_VALUE_UNIT_TIME_NS] = "TIME_NS",
};

// For simplicity, needs to stay in sync w/ typedef enum metrics_v2_metric_type
static const char *const metrics_metric_type_name_mappings[] = {
	[METRIC_VALUE_MONOTONIC] = "MONOTONIC",
	[METRIC_VALUE_NON_MONOTONIC_CURRENT] = "NON_MONOTONIC_CURRENT",
};

namespace libsinsp::metrics {

void metrics_collector::get_rss_vsz_pss_total_memory_and_open_fds(uint32_t &rss, uint32_t &vsz, uint32_t &pss, uint64_t &memory_used_host, uint64_t &open_fds_host)
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

void metrics_collector::get_cpu_usage_and_total_procs(double start_time, double &cpu_usage_perc, double &cpu_usage_perc_total_host, uint32_t &procs_running_host)
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

uint64_t metrics_collector::get_container_memory_usage() const
{
	/* In Kubernetes `container_memory_working_set_bytes` is the memory measure the OOM killer uses
	 * and values from `/sys/fs/cgroup/memory/memory.usage_in_bytes` are close enough.
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

void metrics_collector::snapshot()
{
	m_metrics.clear();
	if (!m_inspector)
	{
		return;
	}

	/* 
	 * libscap metrics 
	 */

	if((m_metrics_flags & METRICS_V2_KERNEL_COUNTERS) || (m_metrics_flags & METRICS_V2_LIBBPF_STATS))
	{
		uint32_t nstats = 0;
		int32_t rc = 0;
		// libscap metrics: m_metrics_flags are pushed down from consumers' input, 
		// libbpf stats only collected when ENGINE_FLAG_BPF_STATS_ENABLED aka `kernel.bpf_stats_enabled = 1`
		const metrics_v2* metrics_v2_scap_snapshot = m_inspector->get_capture_stats_v2(m_metrics_flags, &nstats, &rc);
		if (metrics_v2_scap_snapshot && nstats > 0 && rc == 0)
		{
			// Move existing scap metrics raw buffer into m_metrics vector
			m_metrics.assign(metrics_v2_scap_snapshot, metrics_v2_scap_snapshot + nstats);
		}
	}

	/* 
	 * libsinsp metrics 
	 */

	if((m_metrics_flags & METRICS_V2_RESOURCE_UTILIZATION))
	{
		const scap_agent_info* agent_info = m_inspector->get_agent_info();
		uint32_t rss{0}, vsz{0}, pss{0}, procs_running_host{0};
		uint64_t memory_used_host{0}, open_fds_host{0};
		double cpu_usage_perc{0.0}, cpu_usage_perc_total_host{0.0};
		uint64_t container_memory_usage = get_container_memory_usage();
		metrics_v2_value_unit rss_unit{METRIC_VALUE_UNIT_MEMORY_KILOBYTES}, vsz_unit{METRIC_VALUE_UNIT_MEMORY_KILOBYTES},
		pss_unit{METRIC_VALUE_UNIT_MEMORY_KILOBYTES}, memory_used_host_unit{METRIC_VALUE_UNIT_MEMORY_KILOBYTES}, container_memory_usage_unit{METRIC_VALUE_UNIT_MEMORY_BYTES};
		metrics_v2_value_type rss_type{METRIC_VALUE_TYPE_U32}, vsz_type{METRIC_VALUE_TYPE_U32},
		pss_type{METRIC_VALUE_TYPE_U32}, memory_used_host_type{METRIC_VALUE_TYPE_U32}, container_memory_usage_type{METRIC_VALUE_TYPE_U64};
		get_cpu_usage_and_total_procs(agent_info->start_time, cpu_usage_perc, cpu_usage_perc_total_host, procs_running_host);
		get_rss_vsz_pss_total_memory_and_open_fds(rss, vsz, pss, memory_used_host, open_fds_host);
		if(m_convert_memory_to_mb)
		{
			rss = convert_memory(rss_unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, rss);
			vsz = convert_memory(vsz_unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, vsz);
			pss = convert_memory(pss_unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, pss);
			memory_used_host = convert_memory(memory_used_host_unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, memory_used_host);
			container_memory_usage = convert_memory(container_memory_usage_unit, METRIC_VALUE_UNIT_MEMORY_MEGABYTES, container_memory_usage);
			rss_unit = vsz_unit = pss_unit = memory_used_host_unit = container_memory_usage_unit = METRIC_VALUE_UNIT_MEMORY_MEGABYTES;
			rss_type = vsz_type = pss_type = memory_used_host_type = container_memory_usage_type = METRIC_VALUE_TYPE_D;
		}
		// Resource utilization of the agent itself
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CPU_PERC],
		METRICS_V2_RESOURCE_UTILIZATION, METRIC_VALUE_TYPE_D, METRIC_VALUE_UNIT_PERC, METRIC_VALUE_NON_MONOTONIC_CURRENT, cpu_usage_perc));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS],
		METRICS_V2_RESOURCE_UTILIZATION, rss_type, rss_unit, METRIC_VALUE_NON_MONOTONIC_CURRENT, rss));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ],
		METRICS_V2_RESOURCE_UTILIZATION, vsz_type, vsz_unit, METRIC_VALUE_NON_MONOTONIC_CURRENT, vsz));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS],
		METRICS_V2_RESOURCE_UTILIZATION, pss_type, pss_unit, METRIC_VALUE_NON_MONOTONIC_CURRENT, pss));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY],
		METRICS_V2_RESOURCE_UTILIZATION, container_memory_usage_type, container_memory_usage_unit, METRIC_VALUE_NON_MONOTONIC_CURRENT, container_memory_usage));
		// Resource utilization / load indicators of the underlying host
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST],
		METRICS_V2_RESOURCE_UTILIZATION, METRIC_VALUE_TYPE_D, METRIC_VALUE_UNIT_PERC, METRIC_VALUE_NON_MONOTONIC_CURRENT, cpu_usage_perc_total_host));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_PROCS_HOST],
		METRICS_V2_RESOURCE_UTILIZATION, METRIC_VALUE_TYPE_U32, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, procs_running_host));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST],
		METRICS_V2_RESOURCE_UTILIZATION, memory_used_host_type, memory_used_host_unit, METRIC_VALUE_NON_MONOTONIC_CURRENT, memory_used_host));
		m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST],
		METRICS_V2_RESOURCE_UTILIZATION, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, open_fds_host));
	}

	if((m_metrics_flags & METRICS_V2_STATE_COUNTERS))
	{
		std::shared_ptr<const sinsp_stats_v2> sinsp_stats_v2 = m_inspector->get_sinsp_stats_v2();

		if (!sinsp_stats_v2)
		{
			m_inspector->set_sinsp_stats_v2_enabled();
			sinsp_stats_v2 = m_inspector->get_sinsp_stats_v2();
		}

		if (sinsp_stats_v2)
		{
			uint64_t n_fds = 0;
			uint64_t n_threads = 0;
			if (m_inspector->m_thread_manager)
			{
				n_threads = m_inspector->m_thread_manager->get_thread_count();
				threadinfo_map_t* threadtable = m_inspector->m_thread_manager->get_threads();
				if (threadtable)
				{
					threadtable->loop([&n_fds] (sinsp_threadinfo& tinfo) 
					{
						sinsp_fdtable* fdtable = tinfo.get_fd_table();
						if (fdtable != nullptr)
						{
							n_fds += fdtable->size();
						}
						return true;
					});
				}
			}

			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_THREADS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, n_threads));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_FDS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, n_fds));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_NONCACHED_FD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_noncached_fd_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_CACHED_FD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_cached_fd_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_FAILED_FD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_failed_fd_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_ADDED_FDS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_added_fds));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_REMOVED_FDS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_removed_fds));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_STORED_EVTS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_stored_evts));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_STORE_EVTS_DROPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_store_evts_drops));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_RETRIEVED_EVTS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_retrieved_evts));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_RETRIEVE_EVTS_DROPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_retrieve_evts_drops));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_noncached_thread_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_CACHED_THREAD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_cached_thread_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_FAILED_THREAD_LOOKUPS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_failed_thread_lookups));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_ADDED_THREADS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_added_threads));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_REMOVED_THREADS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U64, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_removed_threads));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U32, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_MONOTONIC, sinsp_stats_v2->m_n_drops_full_threadtable));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U32, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, sinsp_stats_v2->m_n_missing_container_images));
			m_metrics.emplace_back(new_metric(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_CONTAINERS], \
			METRICS_V2_STATE_COUNTERS, METRIC_VALUE_TYPE_U32, METRIC_VALUE_UNIT_COUNT, METRIC_VALUE_NON_MONOTONIC_CURRENT, sinsp_stats_v2->m_n_containers));
		}
	}
}

std::string metrics_collector::convert_metric_to_prometheus_text(std::string metric_name, metrics_v2 metric)
{
	std::string prometheus_text = metric_name;
	prometheus_text += "{raw_name=\"" + std::string(metric.name) + "\",unit=\"" + std::string(metrics_unit_name_mappings[metric.unit]) \
	+ "\",metric_type=\"" + std::string(metrics_metric_type_name_mappings[metric.metric_type]) + "\"} "; // white space at the end important!
	switch (metric.type)
	{
	case METRIC_VALUE_TYPE_U32:
		prometheus_text += std::to_string(metric.value.u32);
		break;
	case METRIC_VALUE_TYPE_S32:
		prometheus_text += std::to_string(metric.value.s32);
		break;
	case METRIC_VALUE_TYPE_U64:
		prometheus_text += std::to_string(metric.value.u64);
		break;
	case METRIC_VALUE_TYPE_S64:
		prometheus_text += std::to_string(metric.value.s64);
		break;
	case METRIC_VALUE_TYPE_D:
		prometheus_text += std::to_string(metric.value.d);
		break;
	case METRIC_VALUE_TYPE_F:
		prometheus_text += std::to_string(metric.value.f);
		break;
	case METRIC_VALUE_TYPE_I:
		prometheus_text += std::to_string(metric.value.i);
		break;
	default:
		break;
	}

	prometheus_text += " ";
	prometheus_text += std::to_string(sinsp_utils::get_current_time_ns());
	return prometheus_text;
}

const std::vector<metrics_v2>& metrics_collector::get_metrics() const
{
	return m_metrics;
}

metrics_collector::metrics_collector(sinsp* inspector, uint32_t flags, bool convert_memory_to_mb) :
	m_inspector(inspector),
	m_metrics_flags(flags),
	m_convert_memory_to_mb(convert_memory_to_mb)
{
}

} // namespace libsinsp::metrics

#endif
