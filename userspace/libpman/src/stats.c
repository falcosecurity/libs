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

#include "state.h"
#include <libscap/scap_assert.h>
#include <libscap/scap.h>
#include <libscap/strl.h>

typedef enum modern_bpf_kernel_counters_stats {
	MODERN_BPF_N_EVTS = 0,
	MODERN_BPF_N_DROPS_BUFFER_TOTAL,
	MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT,
	MODERN_BPF_N_DROPS_SCRATCH_MAP,
	MODERN_BPF_N_DROPS,
	MODERN_BPF_MAX_KERNEL_COUNTERS_STATS
} modern_bpf_kernel_counters_stats;

#ifdef BPF_ITERATOR_SUPPORT
typedef enum modern_bpf_kernel_iter_counters_stats {
	MODERN_BPF_ITER_N_EVTS_TASK = 0,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_PIPE,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_MEMFD,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_REGULAR,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_DIRECTORY,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET6,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_UNIX,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_NETLINK,
	MODERN_BPF_ITER_N_EVTS_TASK_FILE_ANON_INODE,
	MODERN_BPF_ITER_N_DROPS_MAX_EVENT_SIZE,
	MODERN_BPF_ITER_N_DROPS_TASK,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_PIPE,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_MEMFD,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_REGULAR,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_DIRECTORY,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET6,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_UNIX,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_NETLINK,
	MODERN_BPF_ITER_N_DROPS_TASK_FILE_ANON_INODE,
	MODERN_BPF_MAX_KERNEL_ITER_COUNTERS_STATS
} modern_bpf_kernel_iter_counters_stats;
#endif /* BPF_ITERATOR_SUPPORT */

typedef enum modern_bpf_libbpf_stats {
	RUN_CNT = 0,
	RUN_TIME_NS,
	AVG_TIME_NS,
	MODERN_BPF_MAX_LIBBPF_STATS,
} modern_bpf_libbpf_stats;

const char *const modern_bpf_kernel_counters_stats_names[] = {
        [MODERN_BPF_N_EVTS] = N_EVENTS_PREFIX,
        [MODERN_BPF_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
        [MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
        [MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
        [MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
        [MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
        [MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
        [MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
        [MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
        [MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
        [MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT] = "n_drops_buffer_close_exit",
        [MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT] = "n_drops_buffer_proc_exit",
        [MODERN_BPF_N_DROPS_SCRATCH_MAP] = "n_drops_scratch_map",
        [MODERN_BPF_N_DROPS] = "n_drops",
};

#ifdef BPF_ITERATOR_SUPPORT
const char *const modern_bpf_kernel_iter_counters_stats_names[] = {
        [MODERN_BPF_ITER_N_EVTS_TASK] = "n_evts_task",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_PIPE] = "n_evts_task_file_pipe",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_MEMFD] = "n_evts_task_file_memfd",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_REGULAR] = "n_evts_task_file_regular",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_DIRECTORY] = "n_evts_task_file_directory",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET] = "n_evts_task_file_socket_inet",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET6] = "n_evts_task_file_socket_inet6",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_UNIX] = "n_evts_task_file_socket_unix",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_NETLINK] = "n_evts_task_file_socket_netlink",
        [MODERN_BPF_ITER_N_EVTS_TASK_FILE_ANON_INODE] = "n_evts_task_file_anon_inode",
        [MODERN_BPF_ITER_N_DROPS_MAX_EVENT_SIZE] = "n_drops_max_event_size",
        [MODERN_BPF_ITER_N_DROPS_TASK] = "n_drops_task",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_PIPE] = "n_drops_task_file_pipe",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_MEMFD] = "n_drops_task_file_memfd",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_REGULAR] = "n_drops_task_file_regular",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_DIRECTORY] = "n_drops_task_file_directory",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET] = "n_drops_task_file_socket_inet",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET6] = "n_drops_task_file_socket_inet6",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_UNIX] = "n_drops_task_file_socket_unix",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_NETLINK] = "n_drops_task_file_socket_netlink",
        [MODERN_BPF_ITER_N_DROPS_TASK_FILE_ANON_INODE] = "n_drops_task_file_anon_inode",
};
#endif /* BPF_ITERATOR_SUPPORT */

const char *const modern_bpf_libbpf_stats_names[] = {
        [RUN_CNT] = ".run_cnt",          ///< `bpf_prog_info` run_cnt.
        [RUN_TIME_NS] = ".run_time_ns",  ///<`bpf_prog_info` run_time_ns.
        [AVG_TIME_NS] = ".avg_time_ns",  ///< Average time spent in bpg program, calculation:
                                         ///< run_time_ns / run_cnt.
};

int pman_get_scap_stats(struct scap_stats *stats) {
	struct counter_map cnt_map;

	if(!stats) {
		pman_print_errorf("pointer to scap_stats is empty");
		return EINVAL;
	}

	const int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd < 0) {
		const int last_errno = errno;
		pman_print_errorf("unable to get counter maps");
		return last_errno;
	}

	/* Not used in modern probe:
	 * - stats->n_drops_bug
	 * - stats->n_drops_pf
	 * - stats->n_preemptions
	 */

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	for(int index = 0; index < g_state.n_possible_cpus; index++) {
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0) {
			const int last_errno = errno;
			pman_print_errorf("unable to get the counter map for CPU %d", index);
			return last_errno;
		}

		stats->n_evts += cnt_map.n_evts;
		stats->n_drops_buffer += cnt_map.n_drops_buffer;
		stats->n_drops_buffer_clone_fork_exit += cnt_map.n_drops_buffer_clone_fork_exit;
		stats->n_drops_buffer_execve_exit += cnt_map.n_drops_buffer_execve_exit;
		stats->n_drops_buffer_connect_enter += cnt_map.n_drops_buffer_connect_enter;
		stats->n_drops_buffer_connect_exit += cnt_map.n_drops_buffer_connect_exit;
		stats->n_drops_buffer_open_enter += cnt_map.n_drops_buffer_open_enter;
		stats->n_drops_buffer_open_exit += cnt_map.n_drops_buffer_open_exit;
		stats->n_drops_buffer_dir_file_exit += cnt_map.n_drops_buffer_dir_file_exit;
		stats->n_drops_buffer_close_exit += cnt_map.n_drops_buffer_close_exit;
		stats->n_drops_buffer_proc_exit += cnt_map.n_drops_buffer_proc_exit;
		stats->n_drops_buffer_other_interest_exit += cnt_map.n_drops_buffer_other_interest_exit;
		stats->n_drops_scratch_map += cnt_map.n_drops_max_event_size;
		stats->n_drops += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
	}
	return 0;
}

// Initializes global v2 metrics. Returns 0 on success, -1 otherwise.
static int init_metrics_v2(const uint32_t flags) {
	if(g_state.stats) {
		pman_print_errorf("bug: 'metrics_v2' array is already allocated");
		return -1;
	}

	g_state.nstats = 0;

	int nprogs_attached = 0;
	for(int j = 0; j < MODERN_BPF_PROG_ATTACHED_MAX; j++) {
		if(g_state.attached_progs_fds[j] != -1) {
			nprogs_attached++;
		}
	}

	uint32_t per_cpu_stats = 0;
	if(flags & METRICS_V2_KERNEL_COUNTERS_PER_CPU) {
		// At the moment for each available CPU we want:
		// - the number of events.
		// - the number of drops.
		per_cpu_stats = g_state.n_possible_cpus * 2;
	}

	// Account for statistics related to BPF iterator programs.
	uint32_t iter_stats = 0;
#ifdef BPF_ITERATOR_SUPPORT
	if(flags & METRICS_V2_KERNEL_ITER_COUNTERS) {
		iter_stats = MODERN_BPF_MAX_KERNEL_ITER_COUNTERS_STATS;
	}
#endif /* BPF_ITERATOR_SUPPORT */

	const uint32_t n_stats = MODERN_BPF_MAX_KERNEL_COUNTERS_STATS + per_cpu_stats +
	                         (nprogs_attached * MODERN_BPF_MAX_LIBBPF_STATS) + iter_stats;
	struct metrics_v2 *stats = (metrics_v2 *)calloc(n_stats, sizeof(metrics_v2));
	if(!stats) {
		pman_print_errorf("unable to allocate memory for 'metrics_v2' array");
		return -1;
	}

	g_state.nstats = n_stats;
	g_state.stats = stats;
	return 0;
}

static void set_u64_monotonic_kernel_counter(uint32_t pos, uint64_t val, uint32_t metric_flag) {
	g_state.stats[pos].type = METRIC_VALUE_TYPE_U64;
	g_state.stats[pos].flags = metric_flag;
	g_state.stats[pos].unit = METRIC_VALUE_UNIT_COUNT;
	g_state.stats[pos].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
	g_state.stats[pos].value.u64 = val;
}

// Collects stats for `METRICS_V2_KERNEL_COUNTERS` and `METRICS_V2_KERNEL_COUNTERS_PER_CPU` (if
// provided). Returns the strictly-positive number of collected stats on success, -1 otherwise.
static int collect_kernel_counter_stats(const int counter_maps_fd, const bool collect_per_cpu) {
	for(uint32_t stat = 0; stat < MODERN_BPF_MAX_KERNEL_COUNTERS_STATS; stat++) {
		set_u64_monotonic_kernel_counter(stat, 0, METRICS_V2_KERNEL_COUNTERS);
		strlcpy(g_state.stats[stat].name,
		        (char *)modern_bpf_kernel_counters_stats_names[stat],
		        METRIC_NAME_MAX);
	}
	uint32_t collected_stats = MODERN_BPF_MAX_KERNEL_COUNTERS_STATS;

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	struct counter_map cnt_map = {};
	for(uint32_t index = 0; index < g_state.n_possible_cpus; index++) {
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0) {
			pman_print_errorf("unable to get the counter map for CPU %d", index);
			return -1;
		}
		g_state.stats[MODERN_BPF_N_EVTS].value.u64 += cnt_map.n_evts;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_TOTAL].value.u64 += cnt_map.n_drops_buffer;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_clone_fork_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_execve_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER].value.u64 +=
		        cnt_map.n_drops_buffer_connect_enter;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_connect_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER].value.u64 +=
		        cnt_map.n_drops_buffer_open_enter;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_open_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_dir_file_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_other_interest_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_close_exit;
		g_state.stats[MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT].value.u64 +=
		        cnt_map.n_drops_buffer_proc_exit;
		g_state.stats[MODERN_BPF_N_DROPS_SCRATCH_MAP].value.u64 += cnt_map.n_drops_max_event_size;
		g_state.stats[MODERN_BPF_N_DROPS].value.u64 +=
		        (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);

		if(!collect_per_cpu) {
			continue;
		}
		// We set the num events for that CPU.
		set_u64_monotonic_kernel_counter(collected_stats,
		                                 cnt_map.n_evts,
		                                 METRICS_V2_KERNEL_COUNTERS_PER_CPU);
		snprintf(g_state.stats[collected_stats].name,
		         METRIC_NAME_MAX,
		         N_EVENTS_PER_CPU_PREFIX "%d",
		         index);
		collected_stats++;

		// We set the drops for that CPU.
		set_u64_monotonic_kernel_counter(collected_stats,
		                                 cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size,
		                                 METRICS_V2_KERNEL_COUNTERS_PER_CPU);
		snprintf(g_state.stats[collected_stats].name,
		         METRIC_NAME_MAX,
		         N_DROPS_PER_CPU_PREFIX "%d",
		         index);
		collected_stats++;
	}

	return collected_stats;
}

// Collects stats for `METRICS_V2_LIBBPF_STATS`. `base_offset` is the first free position in the
// global v2 metrics array to push libbpf stats to. Returns the strictly-positive number of
// collected stats on success, -1 otherwise.
static int collect_libbpf_stats(const int base_offset) {
	int fd = 0;
	int offset = base_offset;
	for(int bpf_prog = 0; bpf_prog < MODERN_BPF_PROG_ATTACHED_MAX; bpf_prog++) {
		fd = g_state.attached_progs_fds[bpf_prog];
		if(fd < 0) {
			/* landing here means prog was not attached */
			continue;
		}
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		if(bpf_obj_get_info_by_fd(fd, &info, &len)) {
			/* no info for that prog, it seems like a bug, but we can go on */
			continue;
		}

		for(int stat = 0; stat < MODERN_BPF_MAX_LIBBPF_STATS; stat++) {
			if(offset >= g_state.nstats) {
				/* This should never happen, we are doing something wrong */
				pman_print_errorf("no enough space for all the stats");
				return -1;
			}
			g_state.stats[offset].type = METRIC_VALUE_TYPE_U64;
			g_state.stats[offset].flags = METRICS_V2_LIBBPF_STATS;
			strlcpy(g_state.stats[offset].name, info.name, METRIC_NAME_MAX);
			strlcat(g_state.stats[offset].name,
			        modern_bpf_libbpf_stats_names[stat],
			        sizeof(g_state.stats[offset].name));
			switch(stat) {
			case RUN_CNT:
				g_state.stats[offset].unit = METRIC_VALUE_UNIT_COUNT;
				g_state.stats[offset].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
				g_state.stats[offset].value.u64 = info.run_cnt;
				break;
			case RUN_TIME_NS:
				g_state.stats[offset].unit = METRIC_VALUE_UNIT_TIME_NS_COUNT;
				g_state.stats[offset].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
				g_state.stats[offset].value.u64 = info.run_time_ns;
				break;
			case AVG_TIME_NS:
				g_state.stats[offset].unit = METRIC_VALUE_UNIT_TIME_NS;
				g_state.stats[offset].metric_type = METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT;
				g_state.stats[offset].value.u64 = 0;
				if(info.run_cnt > 0) {
					g_state.stats[offset].value.u64 = info.run_time_ns / info.run_cnt;
				}
				break;
			default:
				ASSERT(false);
				break;
			}
			offset++;
		}
	}

	const int collected_stats = offset - base_offset;
	return collected_stats;
}

#ifdef BPF_ITERATOR_SUPPORT

static void set_kernel_iter_counter(const uint32_t base_offset,
                                    const uint32_t stat_index,
                                    const uint64_t val) {
	const char *stat_name = (char *)modern_bpf_kernel_iter_counters_stats_names[stat_index];
	const uint32_t stat_pos = base_offset + stat_index;
	set_u64_monotonic_kernel_counter(stat_pos, val, METRICS_V2_KERNEL_ITER_COUNTERS);
	strlcpy(g_state.stats[stat_pos].name, stat_name, METRIC_NAME_MAX);
}

// Collects stats for `METRICS_V2_KERNEL_ITER_COUNTERS`. `base_offset` is the first free position in
// the global v2 metrics array to push kernel iterator stats to. Returns the strictly-positive
// number of collected stats on success, -1 otherwise.
static int collect_kernel_iter_counter_stats(const int counters_map_fd, const int base_offset) {
	struct iter_counters counters = {};
	uint32_t key;
	for(const uint32_t *prev = NULL; bpf_map_get_next_key(counters_map_fd, prev, &key) == 0;
	    prev = &key) {
		struct iter_counters entry = {};
		if(bpf_map_lookup_elem(counters_map_fd, &key, &entry) < 0) {
			pman_print_errorf("unable to get BPF iterator programs counters for tid %u", key);
			return -1;
		}

		counters.n_evts_task += entry.n_evts_task;
		counters.n_evts_task_file_pipe += entry.n_evts_task_file_pipe;
		counters.n_evts_task_file_memfd += entry.n_evts_task_file_memfd;
		counters.n_evts_task_file_regular += entry.n_evts_task_file_regular;
		counters.n_evts_task_file_directory += entry.n_evts_task_file_directory;
		counters.n_evts_task_file_socket_inet += entry.n_evts_task_file_socket_inet;
		counters.n_evts_task_file_socket_inet6 += entry.n_evts_task_file_socket_inet6;
		counters.n_evts_task_file_socket_unix += entry.n_evts_task_file_socket_unix;
		counters.n_evts_task_file_socket_netlink += entry.n_evts_task_file_socket_netlink;
		counters.n_evts_task_file_anon_inode += entry.n_evts_task_file_anon_inode;
		counters.n_drops_max_event_size += entry.n_drops_max_event_size;
		counters.n_drops_task += entry.n_drops_task;
		counters.n_drops_task_file_pipe += entry.n_drops_task_file_pipe;
		counters.n_drops_task_file_memfd += entry.n_drops_task_file_memfd;
		counters.n_drops_task_file_regular += entry.n_drops_task_file_regular;
		counters.n_drops_task_file_directory += entry.n_drops_task_file_directory;
		counters.n_drops_task_file_socket_inet += entry.n_drops_task_file_socket_inet;
		counters.n_drops_task_file_socket_inet6 += entry.n_drops_task_file_socket_inet6;
		counters.n_drops_task_file_socket_unix += entry.n_drops_task_file_socket_unix;
		counters.n_drops_task_file_socket_netlink += entry.n_drops_task_file_socket_netlink;
		counters.n_drops_task_file_anon_inode += entry.n_drops_task_file_anon_inode;
	}

	set_kernel_iter_counter(base_offset, MODERN_BPF_ITER_N_EVTS_TASK, counters.n_evts_task);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_PIPE,
	                        counters.n_evts_task_file_pipe);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_MEMFD,
	                        counters.n_evts_task_file_memfd);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_REGULAR,
	                        counters.n_evts_task_file_regular);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_DIRECTORY,
	                        counters.n_evts_task_file_directory);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET,
	                        counters.n_evts_task_file_socket_inet);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_INET6,
	                        counters.n_evts_task_file_socket_inet6);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_UNIX,
	                        counters.n_evts_task_file_socket_unix);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_SOCKET_NETLINK,
	                        counters.n_evts_task_file_socket_netlink);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_EVTS_TASK_FILE_ANON_INODE,
	                        counters.n_evts_task_file_anon_inode);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_MAX_EVENT_SIZE,
	                        counters.n_drops_max_event_size);
	set_kernel_iter_counter(base_offset, MODERN_BPF_ITER_N_DROPS_TASK, counters.n_drops_task);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_PIPE,
	                        counters.n_drops_task_file_pipe);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_MEMFD,
	                        counters.n_drops_task_file_memfd);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_REGULAR,
	                        counters.n_drops_task_file_regular);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_DIRECTORY,
	                        counters.n_drops_task_file_directory);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET,
	                        counters.n_drops_task_file_socket_inet);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_INET6,
	                        counters.n_drops_task_file_socket_inet6);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_UNIX,
	                        counters.n_drops_task_file_socket_unix);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_SOCKET_NETLINK,
	                        counters.n_drops_task_file_socket_netlink);
	set_kernel_iter_counter(base_offset,
	                        MODERN_BPF_ITER_N_DROPS_TASK_FILE_ANON_INODE,
	                        counters.n_drops_task_file_anon_inode);

	const int collected_stats = MODERN_BPF_MAX_KERNEL_ITER_COUNTERS_STATS;
	return collected_stats;
}

#endif /* BPF_ITERATOR_SUPPORT */

struct metrics_v2 *pman_get_metrics_v2(uint32_t flags, uint32_t *nstats, int32_t *rc) {
	*rc = SCAP_FAILURE;
	*nstats = 0;

	// If it is the first time we call this function we populate the stats.
	if(g_state.stats == NULL && init_metrics_v2(flags) < 0) {
		return NULL;
	}

	// offset in stats buffer
	int offset = 0;

	/* KERNEL COUNTER STATS */
	if(flags & METRICS_V2_KERNEL_COUNTERS) {
		const int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
		if(counter_maps_fd < 0) {
			pman_print_errorf("unable to get 'counter_maps' fd during kernel stats processing");
			return NULL;
		}

		const bool collect_per_cpu = flags & METRICS_V2_KERNEL_COUNTERS_PER_CPU;
		const int collected_stats = collect_kernel_counter_stats(counter_maps_fd, collect_per_cpu);
		if(collected_stats < 0) {
			return NULL;
		}
		offset = collected_stats;
	}

	/* LIBBPF STATS */

	/* At the time of writing (Apr 2, 2023) libbpf stats are only available on a per program
	 * granularity. This means we cannot measure the statistics for each filler/tail-call
	 * individually. Hopefully someone upstreams such capabilities to libbpf one day :) Meanwhile,
	 * we can simulate perf comparisons between future LSM hooks and tracepoints by leveraging
	 * syscall selection mechanisms `handle->curr_sc_set`.
	 */
	if(flags & METRICS_V2_LIBBPF_STATS) {
		const int collected_stats = collect_libbpf_stats(offset);
		if(collected_stats < 0) {
			return NULL;
		}
		offset += collected_stats;
	}

#ifdef BPF_ITERATOR_SUPPORT
	/* BPF ITERATOR PROGRAMS STATS */
	if(flags & METRICS_V2_KERNEL_ITER_COUNTERS) {
		const int counters_map_fd = bpf_map__fd(g_state.skel->maps.iter_counters_map);
		if(counters_map_fd < 0) {
			pman_print_errorf(
			        "unable to get 'iter_counters_map' fd during kernel stats processing");
			return NULL;
		}

		const int collected_stats = collect_kernel_iter_counter_stats(counters_map_fd, offset);
		if(collected_stats < 0) {
			return NULL;
		}
		offset += collected_stats;
	}
#endif /* BPF_ITERATOR_SUPPORT */

	/* Update with the real number of stats collected */
	*nstats = offset;
	*rc = SCAP_SUCCESS;
	return g_state.stats;
}

int pman_get_n_tracepoint_hit(long *n_events_per_cpu) {
	const int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd < 0) {
		const int last_errno = errno;
		pman_print_errorf("unable to get counter maps");
		return last_errno;
	}

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	struct counter_map cnt_map;
	for(int index = 0; index < g_state.n_possible_cpus; index++) {
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0) {
			const int last_errno = errno;
			pman_print_errorf("unbale to get the counter map for CPU %d", index);
			return last_errno;
		}
		n_events_per_cpu[index] = cnt_map.n_evts;
	}
	return 0;
}
