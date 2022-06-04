#include "state.h"
#include <scap.h>

void libpman__enable_capture()
{
	g_state.skel->bss->g_settings.capture_enabled = true;
}

void libpman__disable_capture()
{
	g_state.skel->bss->g_settings.capture_enabled = false;
}

#ifdef TEST_HELPERS

/* Not used right now */
int libpman__print_stats()
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	long overall_n_drops_buffer = 0;
	long overall_n_drops_max_event_size = 0;
	long overall_n_evts = 0;
	struct counter_map cnt_map;

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		libpman__print_error("unable to get counter maps");
		return errno;
	}

	for(int index = 0; index < g_state.n_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			sprintf(error_message, "unbale to get the counter map for CPU %d", index);
			libpman__print_error((const char *)error_message);
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

int libpman__get_scap_stats(void *scap_stats_struct)
{
	struct scap_stats *stats = (struct scap_stats *)scap_stats_struct;
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	if(!stats)
	{
		libpman__print_error("pointer to scap_stats is empty");
		return errno;
	}

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		libpman__print_error("unable to get counter maps");
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
			sprintf(error_message, "unbale to get the counter map for CPU %d", index);
			libpman__print_error((const char *)error_message);
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

int libpman__get_n_tracepoint_hit(long *n_events_per_cpu)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		libpman__print_error("unable to get counter maps");
		return errno;
	}

	for(int index = 0; index < g_state.n_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			sprintf(error_message, "unbale to get the counter map for CPU %d", index);
			libpman__print_error((const char *)error_message);
			goto clean_print_stats;
		}
		n_events_per_cpu[index] = cnt_map.n_evts;
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}