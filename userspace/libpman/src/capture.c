/*
Copyright (C) 2022 The Falco Authors.

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
#include <libpman.h> // before including scap so that handle_ppm_sc_mask() is not built
#include <scap.h>
#include "strlcpy.h"

/* This function should be idempotent, every time it is called it should enforce again the state */
int pman_enforce_sc_set(bool *sc_set)
{
	/* If we fail at initialization time the BPF skeleton
	 * is not initialized when we stop the capture for example
	 */
	if(!g_state.skel)
	{
		return SCAP_FAILURE;
	}

	/* When we want to disable the capture we receive a NULL pointer here */
	bool empty_sc_set[PPM_SC_MAX] = {0};
	if(!sc_set)
	{
		sc_set = empty_sc_set;
	}

	int ret = 0;
	int syscall_id = 0;
	/* Special tracepoints, their attachment depends on interesting syscalls */
	bool sys_enter = false;
	bool sys_exit = false;
	bool sched_prog_fork = false;
	bool sched_prog_exec = false;

	/* Enforce interesting syscalls */
	for(int sc = 0; sc < PPM_SC_MAX; sc++)
	{
		syscall_id = scap_ppm_sc_to_native_id(sc);
		/* if `syscall_id` is -1 this is not a syscall */
		if(syscall_id == -1)
		{
			continue;
		}

		if(!sc_set[sc])
		{
			pman_mark_single_64bit_syscall(syscall_id, false);
		}
		else
		{
			sys_enter = true;
			sys_exit = true;
			pman_mark_single_64bit_syscall(syscall_id, true);
		}
	}

	if(sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		sched_prog_fork = true;
	}

	if(sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		sched_prog_exec = true;
	}

	/* Enable desired tracepoints */
	if(sys_enter)
		ret = ret ?: pman_attach_syscall_enter_dispatcher();
	else
		ret = ret ?: pman_detach_syscall_enter_dispatcher();

	if(sys_exit)
		ret = ret ?: pman_attach_syscall_exit_dispatcher();
	else
		ret = ret ?: pman_detach_syscall_exit_dispatcher();

	if(sched_prog_fork)
		ret = ret ?: pman_attach_sched_proc_fork();
	else
		ret = ret ?: pman_detach_sched_proc_fork();

	if(sched_prog_exec)
		ret = ret ?: pman_attach_sched_proc_exec();
	else
		ret = ret ?: pman_detach_sched_proc_exec();

	if(sc_set[PPM_SC_SCHED_PROCESS_EXIT])
		ret = ret ?: pman_attach_sched_proc_exit();
	else
		ret = ret ?: pman_detach_sched_proc_exit();

	if(sc_set[PPM_SC_SCHED_SWITCH])
		ret = ret ?: pman_attach_sched_switch();
	else
		ret = ret ?: pman_detach_sched_switch();

	if(sc_set[PPM_SC_PAGE_FAULT_USER])
		ret = ret ?: pman_attach_page_fault_user();
	else
		ret = ret ?: pman_detach_page_fault_user();

	if(sc_set[PPM_SC_PAGE_FAULT_KERNEL])
		ret = ret?: pman_attach_page_fault_kernel();
	else
		ret = ret?: pman_detach_page_fault_kernel();

	if(sc_set[PPM_SC_SIGNAL_DELIVER])
		ret = ret?: pman_attach_signal_deliver();
	else
		ret = ret?: pman_detach_signal_deliver();

	return ret;
}

int pman_get_scap_stats(void *scap_stats_struct)
{
	struct scap_stats *stats = (struct scap_stats *)scap_stats_struct;
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
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		stats->n_evts += cnt_map.n_evts;
		stats->n_drops_buffer += cnt_map.n_drops_buffer;
		stats->n_drops_scratch_map += cnt_map.n_drops_max_event_size;
		stats->n_drops += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}

size_t pman_get_stats_size_hint()
{
	return MAX_KERNEL_COUNTERS_STATS;
}

int pman_get_scap_stats_v2(size_t buf_size, uint32_t flags, void *scap_stats_struct)
{
	struct scap_stats_v2 *stats = (struct scap_stats_v2 *)scap_stats_struct;
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	if(!stats)
	{
		pman_print_error("pointer to scap_stats is empty");
		return errno;
	}

	int counter_maps_fd;
	if ((flags & PPM_SCAP_STATS_KERNEL_COUNTERS))
	{
		counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
		if(counter_maps_fd <= 0)
		{
			pman_print_error("unable to get counter maps");
			return errno;
		}

		/* We always take statistics from all the CPUs, even if some of them are not online.
		* If the CPU is not online the counter map will be empty.
		*/
		for(int stat =  0;  stat < MAX_KERNEL_COUNTERS_STATS; stat++)
		{
			stats[stat].valid = true;
			strlcpy(stats[stat].name, kernel_counters_stats_names[stat], STATS_NAME_MAX);
		}

		for(int index = 0; index < g_state.n_possible_cpus; index++)
		{
			if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
			{
				snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
				pman_print_error((const char *)error_message);
				goto clean_print_stats;
			}
			stats[N_EVTS].u64value += cnt_map.n_evts;
			stats[N_DROPS_BUFFER_TOTAL].u64value += cnt_map.n_drops_buffer;
			stats[N_DROPS_SCRATCH_MAP].u64value += cnt_map.n_drops_max_event_size;
			stats[N_DROPS].u64value += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
		}
		return 0;
	}
	// todo @incertum add libbpf stats in here as well

clean_print_stats:
	close(counter_maps_fd);
	return errno;
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
