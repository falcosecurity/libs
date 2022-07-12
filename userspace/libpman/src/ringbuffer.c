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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "ringbuffer_definitions.h"

/* This must be done to please the verifier! At load-time, the verifier must know the
 * size of a map inside the array.
 */
static int ringbuf_array_set_inner_map()
{
	int err = 0;
	int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, SINGLE_RINGBUF_DIMENSION, NULL);
	if(inner_map_fd < 0)
	{
		pman_print_error("failed to create the dummy inner map");
		return errno;
	}

	/* Set the inner map file descriptor into the outer map. */
	err = bpf_map__set_inner_map_fd(g_state.skel->maps.ringbuf_maps, inner_map_fd);
	if(err)
	{
		pman_print_error("failed to set the dummy inner map inside the ringbuf array");
		close(inner_map_fd);
		return errno;
	}

	/* Save to close it after the loading phase. */
	g_state.inner_ringbuf_map_fd = inner_map_fd;
	return 0;
}

static int ringbuf_array_set_max_entries()
{
	if(bpf_map__set_max_entries(g_state.skel->maps.ringbuf_maps, g_state.n_cpus))
	{
		pman_print_error("unable to set max entries for the ringbuf_array");
		return errno;
	}
	return 0;
}

static int allocate_consumer_producer_positions()
{
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = (unsigned long *)calloc(g_state.n_cpus, sizeof(unsigned long));
	g_state.prod_pos = (unsigned long *)calloc(g_state.n_cpus, sizeof(unsigned long));
	if(g_state.cons_pos == NULL || g_state.prod_pos == NULL)
	{
		pman_print_error("failed to alloc memory for cons_pos and prod_pos");
		return errno;
	}
	return 0;
}

int pman_prepare_ringbuf_array_before_loading()
{
	int err;
	err = ringbuf_array_set_inner_map();
	err = err ?: ringbuf_array_set_max_entries();
	/* Allocate consumer positions and producer positions for the ringbuffer. */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

static int create_first_ringbuffer_map()
{
	int ringubuf_array_fd = -1;
	int ringbuf_map_fd = -1;
	int index = 0;

	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get the ringubuf_array");
		return errno;
	}

	/* create the first ringbuf map. */
	ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, SINGLE_RINGBUF_DIMENSION, NULL);
	if(ringbuf_map_fd <= 0)
	{
		pman_print_error("failed to create the first ringbuf map");
		goto clean_create_first_ringbuffer_map;
	}

	/* add the first ringbuf map into the array. */
	if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
	{
		pman_print_error("failed to add the first ringbuf map into the array");
		goto clean_create_first_ringbuffer_map;
	}

	/* create the ringbuf manager with the first map. */
	g_state.rb_manager = ring_buffer__new(ringbuf_map_fd, NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager");
		goto clean_create_first_ringbuffer_map;
	}
	return 0;

clean_create_first_ringbuffer_map:
	close(ringbuf_map_fd);
	close(ringubuf_array_fd);
	return errno;
}

static int create_remaining_ringbuffer_maps()
{
	int ringubuf_array_fd = -1;
	int ringbuf_map_fd = -1;
	char error_message[MAX_ERROR_MESSAGE_LEN];

	/* the first ringbuf map is already inserted into the array.
	 * See `create_first_ringbuffer_map()` function.
	 */
	int index = 1;

	/* get the ringbuf_array with a map already in it. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get a not empty ringubuf_array");
		return errno;
	}

	/* for all CPUs add the rinugbuf map into the array and add it also
	 * into the ringbuf manager. Please note: we have already initialized the
	 * the ringbuf_array and the manager with the map for the CPU `0`.
	 */
	for(index = 1; index < g_state.n_cpus; index++)
	{
		ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, SINGLE_RINGBUF_DIMENSION, NULL);
		if(ringbuf_map_fd <= 0)
		{
			sprintf(error_message, "failed to create the ringbuf map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_create_remaining_ringbuffer_maps;
		}

		if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
		{
			sprintf(error_message, "failed to add the ringbuf map for CPU %d into the array", index);
			pman_print_error((const char *)error_message);
			goto clean_create_remaining_ringbuffer_maps;
		}

		/* add the new ringbuf map into the manager. */
		if(ring_buffer__add(g_state.rb_manager, ringbuf_map_fd, NULL, NULL))
		{
			sprintf(error_message, "failed to add the ringbuf map for CPU %d into the manager", index);
			pman_print_error((const char *)error_message);
			goto clean_create_remaining_ringbuffer_maps;
		}
	}
	return 0;

clean_create_remaining_ringbuffer_maps:
	close(ringbuf_map_fd);
	close(ringubuf_array_fd);
	return errno;
}

/* Create all the ringbuffer maps inside the ringbuffer_array and assign
 * them to the manager. Note, the first ringbuffer map is separated from
 * the others because we first need to create the ringbuffer manager with
 * just one map `ring_buffer__new`. After having instanciating the manager
 * we can add to it all the other maps with `ring_buffer__add`.
 */
int pman_finalize_ringbuf_array_after_loading()
{
	int err;
	err = create_first_ringbuffer_map();
	err = err ?: create_remaining_ringbuffer_maps();
	return err;
}

static void *ringbuf__search_one_from_ring(struct ring *r, int ring_cnt)
{
	int *len_ptr, len;
	void *sample = NULL;
	int actual_pos = g_state.ringbuf_pos;

	/* If the consumer reach the producer update its position. */
	if(g_state.cons_pos[actual_pos] >= g_state.prod_pos[actual_pos])
	{
		g_state.prod_pos[actual_pos] = smp_load_acquire(r->producer_pos);
	}
	else
	{
		len_ptr = r->data + (g_state.cons_pos[actual_pos] & r->mask);

		len = smp_load_acquire(len_ptr);

		/* Check in the header if the bit is active, sample not committed yet, bail out for now */
		if(len & BPF_RINGBUF_BUSY_BIT)
		{
			goto done;
		}

		g_state.cons_pos[actual_pos] += roundup_len(len);

		/* the sample is not discarded kernel side. */
		if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
		{
			sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
		}
		smp_store_release(r->consumer_pos, g_state.cons_pos[actual_pos]);
	}

done:
	g_state.ringbuf_pos = (actual_pos + 1) % ring_cnt;
	return sample;
}

/* return 0 if a valid event is found, otherwise -1.*/
static int ringbuf__consume_one_event(struct ring_buffer *rb, void **event_ptr, uint16_t *cpu_id)
{
	int starting_pos = g_state.ringbuf_pos;
	int attempts = 0;

	while(true)
	{
		struct ring *ring = &rb->rings[g_state.ringbuf_pos];
		*event_ptr = ringbuf__search_one_from_ring(ring, rb->ring_cnt);
		if(*event_ptr != NULL)
		{
			*cpu_id = g_state.ringbuf_pos;
			return 0;
		}
		if(starting_pos == g_state.ringbuf_pos)
		{
			attempts++;
			/* To be sure that all buffers are empty we have to check two times.
			 * In the worst case, the first time we have to update all producers
			 * positions. If also the second time we don't find any event we are
			 * sure that ring buffers are all empty.
			 */
			if(attempts == 2)
			{
				break;
			}
		}
	}
	*cpu_id = -1;
	return -1;
}

int pman_consume_one_from_buffers(void **event_ptr, uint16_t *cpu_id)
{
	return ringbuf__consume_one_event(g_state.rb_manager, event_ptr, cpu_id);
}