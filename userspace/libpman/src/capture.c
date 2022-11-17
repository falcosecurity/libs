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
#include <scap.h>

int pman_enable_capture(bool *tp_set)
{
	if (!tp_set)
	{
		return pman_attach_all_programs();
	}

	int ret = 0;
	/* Enable requested tracepoints */
	for (int i = 0; i < TP_VAL_MAX && ret == 0; i++)
	{
		if (tp_set[i])
		{
			ret = pman_update_single_program(i, true);
		}
	}
	return ret;
}

int pman_disable_capture()
{
	return pman_detach_all_programs();
}

#ifdef TEST_HELPERS

/* Not used right now */
int pman_print_stats()
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	long overall_n_drops_buffer = 0;
	long overall_n_drops_max_event_size = 0;
	long overall_n_evts = 0;
	struct counter_map cnt_map;

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		pman_print_error("unable to get counter maps");
		return errno;
	}

	for(int index = 0; index < g_state.n_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		overall_n_evts += cnt_map.n_evts;
		overall_n_drops_buffer += cnt_map.n_drops_buffer;
		overall_n_drops_max_event_size += cnt_map.n_drops_max_event_size;
	}
	printf("\noverall_n_evts: %ld\n", overall_n_evts);
	printf("overall_n_drops_max_event_size: %ld\n", overall_n_drops_max_event_size);
	printf("overall_n_drops_buffer: %ld\n", overall_n_drops_buffer);
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}
#endif

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

	for(int index = 0; index < g_state.n_cpus; index++)
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
	}
	return 0;

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

	for(int index = 0; index < g_state.n_cpus; index++)
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
