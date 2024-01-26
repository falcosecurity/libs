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
#include <cmath>
#include <sys/times.h>
#include <sys/stat.h>
#include <libsinsp/metrics_collector.h>
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

namespace libsinsp {
namespace metrics {

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

metrics_collector::metrics_collector(sinsp* inspector, const uint32_t flags) :
	m_inspector(inspector),
	m_metrics_flags((PPM_SCAP_STATS_KERNEL_COUNTERS | PPM_SCAP_STATS_LIBBPF_STATS | PPM_SCAP_STATS_RESOURCE_UTILIZATION | PPM_SCAP_STATS_STATE_COUNTERS))
{
	m_metrics_flags = flags;
}

metrics_collector::~metrics_collector()
{
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

	if((m_metrics_flags & PPM_SCAP_STATS_KERNEL_COUNTERS) || (m_metrics_flags & PPM_SCAP_STATS_LIBBPF_STATS))
	{
		uint32_t nstats = 0;
		int32_t rc = 0;
		// libscap metrics: m_metrics_flags are pushed down from consumers' input, 
		// libbpf stats only collected when ENGINE_FLAG_BPF_STATS_ENABLED aka `kernel.bpf_stats_enabled = 1`
		const scap_stats_v2* scap_stats_v2_snapshot = m_inspector->get_capture_stats_v2(m_metrics_flags, &nstats, &rc);
		if (scap_stats_v2_snapshot && nstats > 0 && rc == 0)
		{
			// Move into m_metrics via std::move
			m_metrics = std::vector<scap_stats_v2>(scap_stats_v2_snapshot, scap_stats_v2_snapshot + nstats);
		}
	}

	/* 
	 * libsinsp metrics 
	 */

	if((m_metrics_flags & PPM_SCAP_STATS_RESOURCE_UTILIZATION))
	{
		const scap_agent_info* agent_info = m_inspector->get_agent_info();
		uint32_t rss = 0;
		uint32_t vsz = 0;
		uint32_t pss = 0;
		uint64_t memory_used_host = 0;
		uint64_t open_fds_host = 0;
		double cpu_usage_perc = 0.0;
		double cpu_usage_perc_total_host = 0.0;
		uint32_t procs_running_host = 0;
		get_cpu_usage_and_total_procs(agent_info->start_time, cpu_usage_perc, cpu_usage_perc_total_host, procs_running_host);
		get_rss_vsz_pss_total_memory_and_open_fds(rss, vsz, pss, memory_used_host, open_fds_host);
		// Resource utilization of the agent itself
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CPU_PERC], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_D, STATS_VALUE_UNIT_PERC, STATS_VALUE_NON_MONOTONIC_CURRENT, cpu_usage_perc));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_RSS], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_MEMORY_KILOBYTES, STATS_VALUE_NON_MONOTONIC_CURRENT, rss));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_VSZ], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_MEMORY_KILOBYTES, STATS_VALUE_NON_MONOTONIC_CURRENT, vsz));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_PSS], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_MEMORY_KILOBYTES, STATS_VALUE_NON_MONOTONIC_CURRENT, pss));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CONTAINER_MEMORY], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_MEMORY_BYTES, STATS_VALUE_NON_MONOTONIC_CURRENT, get_container_memory_usage()));
		// Resource utilization / load indicators of the underlying host
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_CPU_PERC_TOTAL_HOST], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_D, STATS_VALUE_UNIT_PERC, STATS_VALUE_NON_MONOTONIC_CURRENT, cpu_usage_perc_total_host));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_PROCS_HOST], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, procs_running_host));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_MEMORY_TOTAL_HOST], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_MEMORY_KILOBYTES, STATS_VALUE_NON_MONOTONIC_CURRENT, memory_used_host));
		m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_RESOURCE_UTILIZATION_FDS_TOTAL_HOST], \
		PPM_SCAP_STATS_RESOURCE_UTILIZATION, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, open_fds_host));
	}

	if((m_metrics_flags & PPM_SCAP_STATS_STATE_COUNTERS))
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
					threadtable->loop([&] (sinsp_threadinfo& tinfo) {
						sinsp_fdtable* fdtable = tinfo.get_fd_table();
						if (fdtable != nullptr)
						{
							n_fds += fdtable->size();
						}
						return true;
					});
				}
			}

			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_THREADS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, n_threads));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_FDS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, n_fds));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_NONCACHED_FD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_noncached_fd_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_CACHED_FD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_cached_fd_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_FAILED_FD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_failed_fd_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_ADDED_FDS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_added_fds));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_REMOVED_FDS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_removed_fds));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_STORED_EVTS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_stored_evts));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_STORE_EVTS_DROPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_store_evts_drops));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_RETRIEVED_EVTS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_retrieved_evts));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_RETRIEVE_EVTS_DROPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_retrieve_evts_drops));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_NONCACHED_THREAD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_noncached_thread_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_CACHED_THREAD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_cached_thread_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_FAILED_THREAD_LOOKUPS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_failed_thread_lookups));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_ADDED_THREADS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_added_threads));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_REMOVED_THREADS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U64, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_removed_threads));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_DROPS_FULL_THREADTABLE], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_COUNT, STATS_VALUE_MONOTONIC, sinsp_stats_v2->m_n_drops_full_threadtable));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_MISSING_CONTAINER_IMAGES], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, sinsp_stats_v2->m_n_missing_container_images));
			m_metrics.push_back(new_stat(sinsp_stats_v2_resource_utilization_names[SINSP_STATS_V2_N_CONTAINERS], \
			PPM_SCAP_STATS_STATE_COUNTERS, STATS_VALUE_TYPE_U32, STATS_VALUE_UNIT_COUNT, STATS_VALUE_NON_MONOTONIC_CURRENT, sinsp_stats_v2->m_n_containers));
		}
	}
}

const std::vector<scap_stats_v2>& metrics_collector::get_metrics() const
{
	return m_metrics;
}

// Static member init
std::unique_ptr<metrics_collector> metrics_collector::mc_instance = nullptr;

// Factory method implementation
std::unique_ptr<metrics_collector> metrics_collector::create(sinsp* inspector, const uint32_t flags)
{
	if (!mc_instance)
	{
		mc_instance = std::unique_ptr<metrics_collector>(new metrics_collector(inspector, flags));
	}

	return std::move(mc_instance);
}

} // namespace metrics
} // namespace libsinsp

#endif
