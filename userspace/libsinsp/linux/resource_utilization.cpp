#include <libsinsp/linux/resource_utilization.h>

#include <sys/times.h>

void linux_resource_utilization::get_rss_vsz_pss_total_memory_and_open_fds() {
	FILE* f;
	char filepath[512];
	char line[512];

	/*
	 * Get memory usage of the agent itself (referred to as calling process meaning /proc/self/)
	 */

	//  No need for scap_get_host_root since we look at the agents' own process, accessible from
	//  it's own pid namespace (if applicable)
	f = fopen("/proc/self/status", "r");
	if(!f) {
		return;
	}

	while(fgets(line, sizeof(line), f) != nullptr) {
		if(strncmp(line, "VmSize:", 7) == 0) {
			sscanf(line, "VmSize: %" SCNu32, &m_vsz); /* memory size returned in kb */
		} else if(strncmp(line, "VmRSS:", 6) == 0) {
			sscanf(line, "VmRSS: %" SCNu32, &m_rss); /* memory size returned in kb */
		}
	}
	fclose(f);

	//  No need for scap_get_host_root since we look at the agents' own process, accessible from
	//  it's own pid namespace (if applicable)
	f = fopen("/proc/self/smaps_rollup", "r");
	if(!f) {
		ASSERT(false);
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL) {
		if(strncmp(line, "Pss:", 4) == 0) {
			sscanf(line, "Pss: %" SCNu32, &m_pss); /* memory size returned in kb */
			break;
		}
	}
	fclose(f);

	/*
	 * Get total host memory usage
	 */

	// Using scap_get_host_root since we look at the memory usage of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/meminfo", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f) {
		ASSERT(false);
		return;
	}

	uint64_t mem_total, mem_free, mem_buff, mem_cache = 0;

	while(fgets(line, sizeof(line), f) != NULL) {
		if(strncmp(line, "MemTotal:", 9) == 0) {
			sscanf(line, "MemTotal: %" SCNu64, &mem_total); /* memory size returned in kb */
		} else if(strncmp(line, "MemFree:", 8) == 0) {
			sscanf(line, "MemFree: %" SCNu64, &mem_free); /* memory size returned in kb */
		} else if(strncmp(line, "Buffers:", 8) == 0) {
			sscanf(line, "Buffers: %" SCNu64, &mem_buff); /* memory size returned in kb */
		} else if(strncmp(line, "Cached:", 7) == 0) {
			sscanf(line, "Cached: %" SCNu64, &mem_cache); /* memory size returned in kb */
		}
	}
	fclose(f);
	m_host_memory_used = mem_total - mem_free - mem_buff - mem_cache;

	/*
	 * Get total number of allocated file descriptors (not all open files!)
	 * File descriptor is a data structure used by a program to get a handle on a file
	 */

	// Using scap_get_host_root since we look at the total open fds of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/sys/fs/file-nr", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f) {
		ASSERT(false);
		return;
	}
	int matched_fds = fscanf(f, "%" SCNu64, &m_host_open_fds);
	fclose(f);

	if(matched_fds != 1) {
		ASSERT(false);
		return;
	}
}

void linux_resource_utilization::get_cpu_usage_and_total_procs(double start_time) {
	FILE* f;
	char filepath[512];
	char line[512];

	struct tms time;
	if(times(&time) == (clock_t)-1) {
		return;
	}

	/* Number of clock ticks per second, often referred to as USER_HZ / jiffies. */
	long hz = 100;
#ifdef _SC_CLK_TCK
	if((hz = sysconf(_SC_CLK_TCK)) < 0) {
		ASSERT(false);
		hz = 100;
	}
#endif
	/* Current uptime of the host machine in seconds.
	 * /proc/uptime offers higher precision w/ 2 decimals.
	 */

	// Using scap_get_host_root since we look at the uptime of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/uptime", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f) {
		ASSERT(false);
		return;
	}

	double machine_uptime_sec = 0;
	int matched_uptime = fscanf(f, "%lf", &machine_uptime_sec);
	fclose(f);

	if(matched_uptime != 1) {
		ASSERT(false);
		return;
	}

	/*
	 * Get CPU usage of the agent itself (referred to as calling process meaning /proc/self/)
	 */

	/* Current utime is amount of processor time in user mode of calling process. Convert to
	 * seconds. */
	double user_sec = (double)time.tms_utime / hz;

	/* Current stime is amount of time the calling process has been scheduled in kernel mode.
	 * Convert to seconds. */
	double system_sec = (double)time.tms_stime / hz;

	/* CPU usage as percentage is computed by dividing the time the process uses the CPU by the
	 * currently elapsed time of the calling process. Compare to `ps` linux util. */
	double elapsed_sec = machine_uptime_sec - start_time;
	if(elapsed_sec > 0) {
		m_cpu_usage_perc = (double)100.0 * (user_sec + system_sec) / elapsed_sec;
		m_cpu_usage_perc = std::round(m_cpu_usage_perc * 10.0) / 10.0;  // round to 1 decimal
	}

	/*
	 * Get total host CPU usage (all CPUs) as percentage and retrieve number of procs currently
	 * running.
	 */

	// Using scap_get_host_root since we look at the total CPU usage of the underlying host
	snprintf(filepath, sizeof(filepath), "%s/proc/stat", scap_get_host_root());
	f = fopen(filepath, "r");
	if(!f) {
		ASSERT(false);
		return;
	}

	/* Need only first 7 columns of /proc/stat cpu line */
	uint64_t user, nice, system, idle, iowait, irq, softirq = 0;
	while(fgets(line, sizeof(line), f) != NULL) {
		if(strncmp(line, "cpu ", 4) == 0) {
			/* Always first line in /proc/stat file, unit: jiffies */
			sscanf(line,
			       "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
			       " %" SCNu64,
			       &user,
			       &nice,
			       &system,
			       &idle,
			       &iowait,
			       &irq,
			       &softirq);
		} else if(strncmp(line, "procs_running ", 14) == 0) {
			sscanf(line, "procs_running %" SCNu32, &m_host_procs_running);
			break;
		}
	}
	fclose(f);
	auto sum = user + nice + system + idle + iowait + irq + softirq;
	if(sum > 0) {
		m_host_cpu_usage_perc = 100.0 - ((idle * 100.0) / sum);
		m_host_cpu_usage_perc =
		        std::round(m_host_cpu_usage_perc * 10.0) / 10.0;  // round to 1 decimal
	}
}

std::vector<metrics_v2> linux_resource_utilization::to_metrics() {
	std::vector<metrics_v2> metrics;
	metrics.emplace_back(new_metric("cpu_usage_perc",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_D,
	                                METRIC_VALUE_UNIT_PERC,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_cpu_usage_perc));
	metrics.emplace_back(new_metric("memory_rss_kb",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_MEMORY_KIBIBYTES,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_rss));
	metrics.emplace_back(new_metric("memory_vsz_kb",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_MEMORY_KIBIBYTES,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_vsz));
	metrics.emplace_back(new_metric("memory_pss_kb",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_MEMORY_KIBIBYTES,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_pss));
	metrics.emplace_back(new_metric("container_memory_used_bytes",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_MEMORY_BYTES,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_container_memory_used));
	metrics.emplace_back(new_metric("host_cpu_usage_perc",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_D,
	                                METRIC_VALUE_UNIT_PERC,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_host_cpu_usage_perc));
	metrics.emplace_back(new_metric("host_memory_used_kb",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_MEMORY_KIBIBYTES,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_host_memory_used));
	metrics.emplace_back(new_metric("host_procs_running",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U32,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_host_procs_running));
	metrics.emplace_back(new_metric("host_open_fds",
	                                METRICS_V2_RESOURCE_UTILIZATION,
	                                METRIC_VALUE_TYPE_U64,
	                                METRIC_VALUE_UNIT_COUNT,
	                                METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT,
	                                m_host_open_fds));

	return metrics;
}

void linux_resource_utilization::get_container_memory_used() {
	/* In Kubernetes `container_memory_working_set_bytes` is the memory measure the OOM killer uses
	 * and values from `/sys/fs/cgroup/memory/memory.usage_in_bytes` are close enough.
	 *
	 * Please note that `kubectl top pod` numbers would reflect the sum of containers in a pod and
	 * typically libs clients (e.g. Falco) pods contain sidekick containers that use memory as well.
	 * This metric accounts only for the container with the security monitoring agent running.
	 */
	const char* filepath = getenv(SINSP_AGENT_CGROUP_MEM_PATH_ENV_VAR);
	if(filepath == nullptr) {
		// No need for scap_get_host_root since we look at the container pid namespace (if
		// applicable) Known collision for VM memory usage, but this default value is configurable
		filepath = "/sys/fs/cgroup/memory/memory.usage_in_bytes";
	}

	FILE* f = fopen(filepath, "r");
	if(!f) {
		return;
	}

	/* memory size returned in bytes */
	int fscanf_matched = fscanf(f, "%" SCNu64, &m_container_memory_used);
	if(fscanf_matched != 1) {
		m_container_memory_used = 0;
	}

	fclose(f);
}
