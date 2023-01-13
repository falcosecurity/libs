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
#include <ppm_events_public.h>

#include "ringbuffer_definitions.h"

/* Utility functions object loading */

/* This must be done to please the verifier! At load-time, the verifier must know the
 * size of a map inside the array.
 */
static int ringbuf_array_set_inner_map()
{
	int err = 0;
	int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
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
	/* We always allocate a number of entries equal to the available CPUs.
	 * This doesn't mean that we allocate a ring buffer for every available CPU,
	 * it means only that every CPU will have an associated entry.
	 */
	if(bpf_map__set_max_entries(g_state.skel->maps.ringbuf_maps, g_state.n_possible_cpus))
	{
		pman_print_error("unable to set max entries for the ringbuf_array");
		return errno;
	}
	return 0;
}

static int allocate_consumer_producer_positions()
{
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	g_state.prod_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	if(g_state.cons_pos == NULL || g_state.prod_pos == NULL)
	{
		pman_print_error("failed to alloc memory for cons_pos and prod_pos");
		return errno;
	}
	return 0;
}

/* Before loading */
int pman_prepare_ringbuf_array_before_loading()
{
	int err;
	err = ringbuf_array_set_inner_map();
	err = err ?: ringbuf_array_set_max_entries();
	/* Allocate consumer positions and producer positions for the ringbuffer. */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

static bool is_cpu_online(uint16_t cpu_id)
{
	/* CPU 0 is always online */
	if(cpu_id == 0)
	{
		return true;
	}

	char filename[FILENAME_MAX];
	int online = 0;
	snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", cpu_id);
	FILE *fp = fopen(filename, "r");
	if(fp == NULL)
	{
		/* When missing NUMA properties, CPUs do not expose online information.
		 * Fallback at considering them online if we can at least reach their folder.
		 * This is useful for example for raspPi devices.
		 * See: https://github.com/kubernetes/kubernetes/issues/95039
		 */
		snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/", cpu_id);
		if(access(filename, F_OK) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	fscanf(fp, "%d", &online);
	return online == 1;
}

/* After loading */
int pman_finalize_ringbuf_array_after_loading()
{
	int ringubuf_array_fd = -1;
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int *ringbufs_fds = (int *)calloc(g_state.n_required_buffers, sizeof(int));
	bool success = false;

	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);

	/* Create ring buffer maps. */
	for(int i = 0; i < g_state.n_required_buffers; i++)
	{
		ringbufs_fds[i] = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
		if(ringbufs_fds[i] <= 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to create the ringbuf map for CPU '%d'. (If you get memory allocation errors try to reduce the buffer dimension)", i);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}
	}

	/* Create the ringbuf manager */
	g_state.rb_manager = ring_buffer__new(ringbufs_fds[0], NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager.");
		goto clean_percpu_ring_buffers;
	}

	/* Add all remaining buffers into the manager.
	 * We start from 1 because the first one is
	 * used to instantiate the manager.
	 */
	for(int i = 1; i < g_state.n_required_buffers; i++)
	{
		if(ring_buffer__add(g_state.rb_manager, ringbufs_fds[i], NULL, NULL))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the manager", i);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}
	}

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get the ringubuf_array");
		return errno;
	}

	/* We need to associate every CPU to the right ring buffer */
	int ringbuf_id = 0;
	int reached = 0;
	for(int i = 0; i < g_state.n_possible_cpus; i++)
	{
		/* If we want to allocate only buffers for online CPUs and the CPU is online, fill its
		 * ring buffer array entry, otherwise we can go on with the next online CPU
		 */
		if(g_state.allocate_online_only && !is_cpu_online(i))
		{
			continue;
		}

		if(bpf_map_update_elem(ringubuf_array_fd, &i, &ringbufs_fds[ringbuf_id], BPF_ANY))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU '%d' to ringbuf '%d'", i, ringbuf_id);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}

		if(++reached == g_state.cpus_for_each_buffer)
		{
			/* we need to switch to the next buffer */
			reached = 0;
			ringbuf_id++;
		}
	}
	success = true;

clean_percpu_ring_buffers:
	for(int i = 0; i < g_state.n_required_buffers; i++)
	{
		if(ringbufs_fds[i])
		{
			close(ringbufs_fds[i]);
		}
	}
	free(ringbufs_fds);

	if(success)
	{
		return 0;
	}

	close(ringubuf_array_fd);
	if(g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
	return errno;
}

static inline void *ringbuf__get_first_ring_event(struct ring *r, int pos)
{
	int *len_ptr = NULL;
	int len = 0;
	void *sample = NULL;

	/* If the consumer reaches the producer update the producer position to
	 * get the newly collected events.
	 */
	if(g_state.cons_pos[pos] >= g_state.prod_pos[pos])
	{
		g_state.prod_pos[pos] = smp_load_acquire(r->producer_pos);
		return NULL;
	}

	len_ptr = r->data + (g_state.cons_pos[pos] & r->mask);
	len = smp_load_acquire(len_ptr);

	/* The actual event is not yet committed */
	if(len & BPF_RINGBUF_BUSY_BIT)
	{
		return NULL;
	}

	/* Save the size of the event if we need to increment the consumer */
	g_state.last_event_size = roundup_len(len);

	/* the sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
	{
		sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	}

	return sample;
}

static void ringbuf__consume_first_event(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr, int16_t *buffer_id)
{
	uint64_t min_ts = 0xffffffffffffffffLL;
	struct ppm_evt_hdr *tmp_pointer = NULL;
	int tmp_ring = -1;
	unsigned long tmp_cons_increment = 0;

	/* If the last consume operation was successful we can push the consumer position */
	if(g_state.last_ring_read != -1)
	{
		struct ring *r = &(rb->rings[g_state.last_ring_read]);
		g_state.cons_pos[g_state.last_ring_read] += g_state.last_event_size;
		smp_store_release(r->consumer_pos, g_state.cons_pos[g_state.last_ring_read]);
	}

	for(uint16_t pos = 0; pos < rb->ring_cnt; pos++)
	{
		*event_ptr = ringbuf__get_first_ring_event(&rb->rings[pos], pos);

		/* if NULL search for events in another buffer */
		if(*event_ptr == NULL)
		{
			continue;
		}

		if((*event_ptr)->ts < min_ts)
		{
			min_ts = (*event_ptr)->ts;
			tmp_pointer = *event_ptr;
			tmp_ring = pos;
			tmp_cons_increment = g_state.last_event_size;
		}
	}

	*event_ptr = tmp_pointer;
	*buffer_id = tmp_ring;
	g_state.last_ring_read = tmp_ring;
	g_state.last_event_size = tmp_cons_increment;
}

/* Consume */
void pman_consume_first_event(void **event_ptr, int16_t *buffer_id)
{
	ringbuf__consume_first_event(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, buffer_id);
}

#ifdef TEST_HELPERS

/* The buffer is full if the remaining size is less than the dimension
 * of the event we want to push, this helper can be used when the dimension
 * of the event pushed is always the same.
 */
static bool pman_is_ringbuffer_full(int ring_num, unsigned long threshold)
{
	if(ring_num < 0 || ring_num >= g_state.n_possible_cpus)
	{
		return -1;
	}

	struct ring_buffer *rb = g_state.rb_manager;
	struct ring *ring = &rb->rings[ring_num];
	unsigned long p = 0;
	unsigned long c = 0;
	p = smp_load_acquire(ring->producer_pos);
	c = smp_load_acquire(ring->consumer_pos);
	unsigned long dim = ring->mask;
	unsigned long reserved = (p >= c) ? p - c : dim - c + p;
	unsigned long free = dim - reserved;
	/* We need this print otherwise the test won't work! */
	printf("Ring (%d): producer %ld, consumer: %ld, reserved: %ld\n", ring_num, p, c, reserved);
	return free < threshold;
}

bool pman_are_all_ringbuffers_full(unsigned long threshold)
{
	int pos = 0;
	int attempt = 0;

	/* Performs 3 attempts just to be sure that all the buffers are empty. */
	while(pos < g_state.n_possible_cpus)
	{
		if(!pman_is_ringbuffer_full(pos, threshold))
		{
			return false;
		}

		pos++;

		if(pos == g_state.n_possible_cpus && attempt != 2)
		{
			printf("Stable, attempt %d\n", attempt);
			pos = 0;
			attempt++;
		}
	}
	return true;
}

unsigned long pman_get_producer_pos(int ring_num)
{
	struct ring_buffer *rb = g_state.rb_manager;
	struct ring *ring = &rb->rings[ring_num];
	return smp_load_acquire(ring->producer_pos);
}

static inline void *ringbuf__search_one_from_ring(struct ring *r, int ring_cnt)
{
	int *len_ptr = NULL;
	int len = 0;
	void *sample = NULL;
	int actual_pos = g_state.ringbuf_pos;

	/* If we enter here again we have read the previous event on this buffer so we can move
	 * the consumer position.
	 */
	smp_store_release(r->consumer_pos, g_state.cons_pos[actual_pos]);

	/* If the consumer reaches the producer update its position. */
	if(g_state.cons_pos[actual_pos] >= g_state.prod_pos[actual_pos])
	{
		g_state.prod_pos[actual_pos] = smp_load_acquire(r->producer_pos);
	}
	else
	{
		len_ptr = r->data + (g_state.cons_pos[actual_pos] & r->mask);

		/* These are the first 4 bytes of the ring buffer record header:
		 *
		 * struct bpf_ringbuf_hdr {
		 *		u32 len;
		 *		u32 pg_off;
		 *	};
		 *
		 * So the event can have at maximum this dimension: `(UINT_MAX/4)` since
		 * the 2 top bits are reserved for `BPF_RINGBUF_BUSY_BIT` and `BPF_RINGBUF_DISCARD_BIT`.
		 *
		 * These 2 operations allow us to remove the 2 top bits obtaining the real size of our event:
		 * len <<= 2;
		 * len >>= 2;
		 */
		len = smp_load_acquire(len_ptr);

		/* Check in the header if the bit is active, sample not committed yet, bailout for now */
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
	}

done:
	/* We change the buffer after every event we catch */
	g_state.ringbuf_pos = (actual_pos + 1) % ring_cnt;
	return sample;
}

/* return 0 if a valid event is found, otherwise -1. */
static int ringbuf__consume_one_event(struct ring_buffer *rb, void **event_ptr, uint16_t *cpu_id)
{
	int ringbuf_pos = g_state.ringbuf_pos;
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
		if(ringbuf_pos == g_state.ringbuf_pos)
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

/* This API must be used if we want to get just one event from the buffer and we don't care about
 * the timestamp of the event.
 */
int pman_consume_one_from_buffers(void **event_ptr, uint16_t *cpu_id)
{
	return ringbuf__consume_one_event(g_state.rb_manager, event_ptr, cpu_id);
}

#endif
