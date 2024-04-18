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

typedef enum modern_bpf_kernel_counters_stats
{
	MODERN_BPF_N_EVTS = 0,
	MODERN_BPF_N_DROPS_BUFFER_TOTAL,
	MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_EXECVE_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER,
	MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT,
	MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT,
	MODERN_BPF_N_DROPS_SCRATCH_MAP,
	MODERN_BPF_N_DROPS,
	MODERN_BPF_MAX_KERNEL_COUNTERS_STATS
} modern_bpf_kernel_counters_stats;

typedef enum modern_bpf_libbpf_stats
{
	RUN_CNT = 0,
	RUN_TIME_NS,
	AVG_TIME_NS,
	MODERN_BPF_MAX_LIBBPF_STATS,
} modern_bpf_libbpf_stats;

const char *const modern_bpf_kernel_counters_stats_names[] = {
	[MODERN_BPF_N_EVTS] = "n_evts",
	[MODERN_BPF_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[MODERN_BPF_N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT] = "n_drops_buffer_close_exit",
	[MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT] = "n_drops_buffer_proc_exit",
	[MODERN_BPF_N_DROPS_SCRATCH_MAP] = "n_drops_scratch_map",
	[MODERN_BPF_N_DROPS] = "n_drops",
};

const char *const modern_bpf_libbpf_stats_names[] = {
	[RUN_CNT] = ".run_cnt",		///< `bpf_prog_info` run_cnt.
	[RUN_TIME_NS] = ".run_time_ns", ///<`bpf_prog_info` run_time_ns.
	[AVG_TIME_NS] = ".avg_time_ns", ///< Average time spent in bpg program, calculation: run_time_ns / run_cnt.
};

int pman_get_scap_stats(struct scap_stats *stats)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	if(!stats)
	{
		pman_print_error("pointer to scap_stats is empty");
		return errno;
	}

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		pman_print_error("unable to get counter maps");
		return errno;
	}

	/* Not used in modern probe:
	 * - stats->n_drops_bug
	 * - stats->n_drops_pf
	 * - stats->n_preemptions
	 */

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	for(int index = 0; index < g_state.n_possible_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		stats->n_evts += cnt_map.n_evts;
		stats->n_drops_buffer += cnt_map.n_drops_buffer;
		stats->n_drops_buffer_clone_fork_enter += cnt_map.n_drops_buffer_clone_fork_enter;
		stats->n_drops_buffer_clone_fork_exit += cnt_map.n_drops_buffer_clone_fork_exit;
		stats->n_drops_buffer_execve_enter += cnt_map.n_drops_buffer_execve_enter;
		stats->n_drops_buffer_execve_exit += cnt_map.n_drops_buffer_execve_exit;
		stats->n_drops_buffer_connect_enter += cnt_map.n_drops_buffer_connect_enter;
		stats->n_drops_buffer_connect_exit += cnt_map.n_drops_buffer_connect_exit;
		stats->n_drops_buffer_open_enter += cnt_map.n_drops_buffer_open_enter;
		stats->n_drops_buffer_open_exit += cnt_map.n_drops_buffer_open_exit;
		stats->n_drops_buffer_dir_file_enter += cnt_map.n_drops_buffer_dir_file_enter;
		stats->n_drops_buffer_dir_file_exit += cnt_map.n_drops_buffer_dir_file_exit;
		stats->n_drops_buffer_other_interest_enter += cnt_map.n_drops_buffer_other_interest_enter;
		stats->n_drops_buffer_close_exit += cnt_map.n_drops_buffer_close_exit;
		stats->n_drops_buffer_proc_exit += cnt_map.n_drops_buffer_proc_exit;
		stats->n_drops_buffer_other_interest_exit += cnt_map.n_drops_buffer_other_interest_exit;
		stats->n_drops_scratch_map += cnt_map.n_drops_max_event_size;
		stats->n_drops += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}

struct metrics_v2 *pman_get_metrics_v2(uint32_t flags, uint32_t *nstats, int32_t *rc)
{
	*rc = SCAP_FAILURE;
	/* This is the expected number of stats */
	*nstats = (MODERN_BPF_MAX_KERNEL_COUNTERS_STATS + (g_state.n_attached_progs * MODERN_BPF_MAX_LIBBPF_STATS));
	/* offset in stats buffer */
	int offset = 0;

	/* If it is the first time we call this function we populate the stats */
	if(g_state.stats == NULL)
	{
		g_state.stats = (metrics_v2 *)calloc(*nstats, sizeof(metrics_v2));
		if(g_state.stats == NULL)
		{
			pman_print_error("unable to allocate memory for 'metrics_v2' array");
			return NULL;
		}
	}

	/* KERNEL COUNTER STATS */

	if(flags & METRICS_V2_KERNEL_COUNTERS)
	{
		char error_message[MAX_ERROR_MESSAGE_LEN];
		int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
		if(counter_maps_fd <= 0)
		{
			pman_print_error("unable to get 'counter_maps' fd during kernel stats processing");
			return NULL;
		}

		for(uint32_t stat = 0; stat < MODERN_BPF_MAX_KERNEL_COUNTERS_STATS; stat++)
		{
			g_state.stats[stat].type = METRIC_VALUE_TYPE_U64;
			g_state.stats[stat].flags = METRICS_V2_KERNEL_COUNTERS;
			g_state.stats[stat].unit = METRIC_VALUE_UNIT_COUNT;
			g_state.stats[stat].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
			g_state.stats[stat].value.u64 = 0;
			strlcpy(g_state.stats[stat].name, modern_bpf_kernel_counters_stats_names[stat], METRIC_NAME_MAX);
		}

		/* We always take statistics from all the CPUs, even if some of them are not online.
		 * If the CPU is not online the counter map will be empty.
		 */
		struct counter_map cnt_map;
		for(uint32_t index = 0; index < g_state.n_possible_cpus; index++)
		{
			if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
			{
				snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get the counter map for CPU %d", index);
				pman_print_error((const char *)error_message);
				close(counter_maps_fd);
				return NULL;
			}
			g_state.stats[MODERN_BPF_N_EVTS].value.u64 += cnt_map.n_evts;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_TOTAL].value.u64 += cnt_map.n_drops_buffer;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER].value.u64 += cnt_map.n_drops_buffer_clone_fork_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT].value.u64 += cnt_map.n_drops_buffer_clone_fork_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_EXECVE_ENTER].value.u64 += cnt_map.n_drops_buffer_execve_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_EXECVE_EXIT].value.u64 += cnt_map.n_drops_buffer_execve_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CONNECT_ENTER].value.u64 += cnt_map.n_drops_buffer_connect_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CONNECT_EXIT].value.u64 += cnt_map.n_drops_buffer_connect_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OPEN_ENTER].value.u64 += cnt_map.n_drops_buffer_open_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OPEN_EXIT].value.u64 += cnt_map.n_drops_buffer_open_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_ENTER].value.u64 += cnt_map.n_drops_buffer_dir_file_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_DIR_FILE_EXIT].value.u64 += cnt_map.n_drops_buffer_dir_file_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER].value.u64 += cnt_map.n_drops_buffer_other_interest_enter;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT].value.u64 += cnt_map.n_drops_buffer_other_interest_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_CLOSE_EXIT].value.u64 += cnt_map.n_drops_buffer_close_exit;
			g_state.stats[MODERN_BPF_N_DROPS_BUFFER_PROC_EXIT].value.u64 += cnt_map.n_drops_buffer_proc_exit;
			g_state.stats[MODERN_BPF_N_DROPS_SCRATCH_MAP].value.u64 += cnt_map.n_drops_max_event_size;
			g_state.stats[MODERN_BPF_N_DROPS].value.u64 += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
		}
		offset = MODERN_BPF_MAX_KERNEL_COUNTERS_STATS;
	}

	/* LIBBPF STATS */

	/* At the time of writing (Apr 2, 2023) libbpf stats are only available on a per program granularity.
	 * This means we cannot measure the statistics for each filler/tail-call individually.
	 * Hopefully someone upstreams such capabilities to libbpf one day :)
	 * Meanwhile, we can simulate perf comparisons between future LSM hooks and sys enter and exit tracepoints
	 * via leveraging syscall selection mechanisms `handle->curr_sc_set`.
	 */
	if((flags & METRICS_V2_LIBBPF_STATS))
	{
		for(int bpf_prog = 0; bpf_prog < MODERN_BPF_PROG_ATTACHED_MAX; bpf_prog++)
		{
			int fd = g_state.attached_progs_fds[bpf_prog];
			if(fd < 0)
			{
				/* landing here means prog was not attached */
				continue;
			}
			struct bpf_prog_info info = {};
			__u32 len = sizeof(info);
			if((bpf_obj_get_info_by_fd(fd, &info, &len)))
			{
				/* no info for that prog, it seems like a bug but we can go on */
				continue;
			}

			for(int stat = 0; stat < MODERN_BPF_MAX_LIBBPF_STATS; stat++)
			{
				if(offset >= *nstats)
				{
					/* This should never happen we are reading something wrong */
					pman_print_error("no enough space for all the stats");
					return NULL;
				}
				g_state.stats[offset].type = METRIC_VALUE_TYPE_U64;
				g_state.stats[offset].flags = METRICS_V2_LIBBPF_STATS;
				strlcpy(g_state.stats[offset].name, info.name, METRIC_NAME_MAX);
				switch(stat)
				{
				case RUN_CNT:
					strlcat(g_state.stats[offset].name, modern_bpf_libbpf_stats_names[RUN_CNT], sizeof(g_state.stats[offset].name));
					g_state.stats[stat].flags = METRICS_V2_KERNEL_COUNTERS;
					g_state.stats[stat].unit = METRIC_VALUE_UNIT_COUNT;
					g_state.stats[stat].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
					g_state.stats[offset].value.u64 = info.run_cnt;
					break;
				case RUN_TIME_NS:
					strlcat(g_state.stats[offset].name, modern_bpf_libbpf_stats_names[RUN_TIME_NS], sizeof(g_state.stats[offset].name));
					g_state.stats[stat].unit = METRIC_VALUE_UNIT_TIME_NS_COUNT;
					g_state.stats[stat].metric_type = METRIC_VALUE_METRIC_TYPE_MONOTONIC;
					g_state.stats[offset].value.u64 = info.run_time_ns;
					break;
				case AVG_TIME_NS:
					strlcat(g_state.stats[offset].name, modern_bpf_libbpf_stats_names[AVG_TIME_NS], sizeof(g_state.stats[offset].name));
					g_state.stats[stat].unit = METRIC_VALUE_UNIT_TIME_NS;
					g_state.stats[stat].metric_type = METRIC_VALUE_METRIC_TYPE_NON_MONOTONIC_CURRENT;
					g_state.stats[offset].value.u64 = 0;
					if(info.run_cnt > 0)
					{
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
	}

	/* Update with the real number of stats collected */
	*nstats = offset;
	*rc = SCAP_SUCCESS;
	return g_state.stats;
}

int pman_get_n_tracepoint_hit(long *n_events_per_cpu)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		pman_print_error("unable to get counter maps");
		return errno;
	}

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	for(int index = 0; index < g_state.n_possible_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		n_events_per_cpu[index] = cnt_map.n_evts;
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}
