#pragma once

// Utility function to calculate CPU usage
int get_cpu_usage_percent();

typedef struct {
	unsigned long vm_size_in_pages;  ///< `size` column in `/proc/pid/statm`.
	unsigned long vm_rss_in_pages;   ///< `resident` column in `/proc/pid/statm`.
} mem_stats_t;

// Returns stats about memory usage.
int get_mem_stats(mem_stats_t* stats);
