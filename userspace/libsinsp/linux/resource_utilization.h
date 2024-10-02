#include <libsinsp/metrics_collector.h>

class linux_resource_utilization : libs::metrics::libsinsp_metrics {
public:
	linux_resource_utilization(double start_time) {
		get_cpu_usage_and_total_procs(start_time);
		get_rss_vsz_pss_total_memory_and_open_fds();
		get_container_memory_used();
	}

	std::vector<metrics_v2> to_metrics();

private:
	void get_cpu_usage_and_total_procs(double start_time);
	void get_rss_vsz_pss_total_memory_and_open_fds();
	void get_container_memory_used();

	double m_cpu_usage_perc{};  ///< Current CPU usage, `ps` util like calculation for the calling
	                            ///< process (/proc/self), unit: percentage of one CPU.

	uint32_t m_rss{};  ///< Current RSS (Resident Set Size), calculated based on /proc/self/status
	                   ///< info, unit: kb.
	uint32_t m_vsz{};  ///< Current VSZ (Virtual Memory Size), calculated based on /proc/self/status
	                   ///< info, unit: kb.
	uint32_t m_pss{};  ///< Current PSS (Proportional Set Size), calculated based on
	                   ///< /proc/self/smaps_rollup info, unit: kb.

	uint64_t m_container_memory_used{};  ///< Cgroup current memory used, default Kubernetes
	                                     ///< /sys/fs/cgroup/memory/memory.usage_in_bytes, unit:
	                                     ///< bytes.

	double m_host_cpu_usage_perc{};   ///< Current total host CPU usage (all CPUs), calculated based
	                                  ///< on ${HOST_ROOT}/proc/stat info, unit: percentage.
	uint64_t m_host_memory_used{};    ///< Current total memory used out of available host memory,
	                                  ///< calculated based on ${HOST_ROOT}/proc/meminfo info, unit:
	                                  ///< kb.
	uint32_t m_host_procs_running{};  ///< Number of processes currently running on CPUs on the
	                                  ///< host, retrieved from ${HOST_ROOT}/proc/stat line
	                                  ///< `procs_running`, unit: count.
	uint64_t m_host_open_fds{};       ///< Number of allocated fds on the host, retrieved from
	                                  ///< ${HOST_ROOT}/proc/sys/fs/file-nr, unit: count.
};
