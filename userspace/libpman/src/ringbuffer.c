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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <ringbuffer_debug_macro.h>
#include <driver/ppm_events_public.h>

#include "ringbuffer_definitions.h"
#include "support_probing.h"

#include <libpman.h>
/* Utility functions object loading */

/* This must be done to please the verifier! At load-time, the verifier must know the
 * size of a map inside the array.
 */
static int ringbuf_array_set_inner_map(const struct bpf_probe *probe,
                                       const unsigned long buffer_bytes_dim,
                                       int32_t *inner_ringbuf_map_fd) {
	const int inner_map_fd =
	        bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, buffer_bytes_dim, NULL);
	if(inner_map_fd < 0) {
		pman_print_errorf("failed to create the dummy inner map with buffer bytes dim %lu",
		                  buffer_bytes_dim);
		return errno;
	}

	/* Set the inner map file descriptor into the outer map. */
	const int err = bpf_map__set_inner_map_fd(probe->maps.ringbuf_maps, inner_map_fd);
	if(err) {
		pman_print_errorf("failed to set the dummy inner map inside the ringbuf array");
		close(inner_map_fd);
		return errno;
	}

	/* Save to close it after the loading phase. */
	*inner_ringbuf_map_fd = inner_map_fd;
	return 0;
}

static int ringbuf_array_set_max_entries(const struct bpf_probe *probe,
                                         const uint32_t max_entries) {
	if(bpf_map__set_max_entries(probe->maps.ringbuf_maps, max_entries)) {
		pman_print_errorf("unable to set max entries to %u for the ringbuf_array", max_entries);
		return errno;
	}
	return 0;
}

static int allocate_consumer_producer_positions() {
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	g_state.prod_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	if(g_state.cons_pos == NULL || g_state.prod_pos == NULL) {
		pman_print_errorf("failed to alloc memory for cons_pos and prod_pos");
		return errno;
	}
	return 0;
}

/* Before loading */
int pman_prepare_ringbuf_array_before_loading() {
	int err = ringbuf_array_set_inner_map(g_state.skel,
	                                      g_state.buffer_bytes_dim,
	                                      &g_state.inner_ringbuf_map_fd);
	/* We always allocate a number of entries equal to the available CPUs. This doesn't mean that we
	 * allocate a ring buffer for every available CPU, it means only that every CPU will have an
	 * associated entry.
	 */
	const int16_t buffers_num = pman_is_cpus_to_ringbufs_mapping_disabled()
	                                    ? g_state.n_required_buffers
	                                    : g_state.n_possible_cpus;
	err = err ?: ringbuf_array_set_max_entries(g_state.skel, buffers_num);
	/* Allocate consumer positions and producer positions for the ringbuffer. */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

#ifdef BPF_ITERATOR_SUPPORT
// Variant of `pman_prepare_ringbuf_array_before_loading()` used for testing BPF iterator programs
// support.
int iter_support_probing__prepare_ringbuf_array_before_loading(
        struct iter_support_probing_ctx *ctx) {
	const unsigned long page_size = sysconf(_SC_PAGESIZE);
	int err = ringbuf_array_set_inner_map(ctx->probe, page_size, &ctx->inner_ringbuf_map_fd);
	err = err ?: ringbuf_array_set_max_entries(ctx->probe, 1);
	return err;
}
#endif  // BPF_ITERATOR_SUPPORT

static bool is_cpu_online(uint16_t cpu_id) {
	/* CPU 0 is always online */
	if(cpu_id == 0) {
		return true;
	}

	char filename[FILENAME_MAX];
	int online = 0;
	snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", cpu_id);
	FILE *fp = fopen(filename, "r");
	if(fp == NULL) {
		/* When missing NUMA properties, CPUs do not expose online information.
		 * Fallback at considering them online if we can at least reach their folder.
		 * This is useful for example for raspPi devices.
		 * See: https://github.com/kubernetes/kubernetes/issues/95039
		 */
		snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/", cpu_id);
		if(access(filename, F_OK) == 0) {
			return true;
		} else {
			return false;
		}
	}

	if(fscanf(fp, "%d", &online) != 1) {
		online = 0;
	}
	fclose(fp);
	return online == 1;
}

static int init_ringbuf_handles() {
	const uint16_t ringbufs_num = g_state.rb_manager->ring_cnt;
	g_state.ringbuf_handles = malloc(ringbufs_num * sizeof(pman_ringbuf_t));
	if(g_state.ringbuf_handles == NULL) {
		pman_print_errorf("failed to allocate memory for ringbuf_handles");
		return errno;
	}
	for(int i = 0; i < g_state.rb_manager->ring_cnt; i++) {
		// For the moment, use the ring buffer index as handle.
		g_state.ringbuf_handles[i] = i;
	}
	g_state.n_reserved_ringbuf_handles = 0;
	return 0;
}

/* After loading */
int pman_finalize_ringbuf_array_after_loading() {
	int last_errno = EINVAL;
	bool success = false;
	const bool is_cpus_to_ringbufs_mapping_disabled = pman_is_cpus_to_ringbufs_mapping_disabled();

	int ringbuf_array_fd;

	int *ringbufs_fds = (int *)malloc(g_state.n_required_buffers * sizeof(int));
	if(ringbufs_fds == NULL) {
		last_errno = errno;
		pman_print_errorf("failed to allocate the ringbufs_fds array");
		return last_errno;
	}

	/* Initialize all fds to -1 so we can distinguish between valid and invalid ones. */
	memset(ringbufs_fds, -1, g_state.n_required_buffers * sizeof(int));

	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);
	g_state.inner_ringbuf_map_fd = -1;

	/* Create ring buffer maps. */
	for(int i = 0; i < g_state.n_required_buffers; i++) {
		ringbufs_fds[i] =
		        bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
		if(ringbufs_fds[i] < 0) {
			last_errno = errno;
			pman_print_errorf(
			        "failed to create the ringbuf [%d] map. (If you get memory allocation "
			        "errors try to reduce the buffer dimension)",
			        i);
			goto clean_percpu_ring_buffers;
		}
	}

	/* Create the ringbuf manager */
	g_state.rb_manager = ring_buffer__new(ringbufs_fds[0], NULL, NULL, NULL);
	if(!g_state.rb_manager) {
		last_errno = errno;
		pman_print_errorf("failed to instantiate the ringbuf manager.");
		goto clean_percpu_ring_buffers;
	}

	/* Add all remaining buffers into the manager.
	 * We start from 1 because the first one is
	 * used to instantiate the manager.
	 */
	for(int i = 1; i < g_state.n_required_buffers; i++) {
		if(ring_buffer__add(g_state.rb_manager, ringbufs_fds[i], NULL, NULL)) {
			last_errno = errno;
			pman_print_errorf("failed to add the ringbuf [%d] map into the manager", i);
			goto clean_percpu_ring_buffers;
		}
	}

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringbuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringbuf_array_fd < 0) {
		last_errno = errno;
		pman_print_errorf("failed to get the ringbuf_array");
		goto clean_percpu_ring_buffers;
	}

	if(is_cpus_to_ringbufs_mapping_disabled) {
		for(int i = 0; i < g_state.n_required_buffers; i++) {
			if(bpf_map_update_elem(ringbuf_array_fd, &i, &ringbufs_fds[i], BPF_ANY)) {
				last_errno = errno;
				pman_print_errorf("failed to add ringbuf [%d] to ringbuf map", i);
				goto clean_percpu_ring_buffers;
			}
		}
		if(init_ringbuf_handles()) {
			goto clean_percpu_ring_buffers;
		}
		success = true;
		goto clean_percpu_ring_buffers;
	}

	/* We need to associate every CPU to the right ring buffer */
	int ringbuf_id = 0;
	int reached = 0;
	for(int i = 0; i < g_state.n_possible_cpus; i++) {
		/* If we want to allocate only buffers for online CPUs and the CPU is online, fill its
		 * ring buffer array entry, otherwise we can go on with the next online CPU
		 */
		if(g_state.allocate_online_only && !is_cpu_online(i)) {
			continue;
		}

		if(ringbuf_id >= g_state.n_required_buffers) {
			/* If we arrive here it means that we have too many CPUs for our allocated ring buffers
			 * so probably we faced a CPU hotplug.
			 */
			pman_print_errorf(
			        "the actual system configuration requires more than '%d' ring buffers",
			        g_state.n_required_buffers);
			goto clean_percpu_ring_buffers;
		}

		if(bpf_map_update_elem(ringbuf_array_fd, &i, &ringbufs_fds[ringbuf_id], BPF_ANY)) {
			last_errno = errno;
			pman_print_errorf("failed to add the ringbuf map for CPU [%d] to ringbuf [%d]",
			                  i,
			                  ringbuf_id);
			goto clean_percpu_ring_buffers;
		}

		if(++reached == g_state.cpus_for_each_buffer) {
			/* we need to switch to the next buffer */
			reached = 0;
			ringbuf_id++;
		}
	}
	if(init_ringbuf_handles()) {
		goto clean_percpu_ring_buffers;
	}
	success = true;

clean_percpu_ring_buffers:
	for(int i = 0; i < g_state.n_required_buffers; i++) {
		if(ringbufs_fds[i] >= 0) {
			close(ringbufs_fds[i]);
		}
	}
	free(ringbufs_fds);

	if(success) {
		return 0;
	}

	if(g_state.rb_manager) {
		ring_buffer__free(g_state.rb_manager);
	}
	return last_errno;
}

pman_ringbuf_t PMAN_INVALID_RING_BUFFER_HANDLE = 0xFFFF;

uint16_t pman_get_n_allocated_ringbuf_handles() {
	return g_state.rb_manager->ring_cnt;
}

pman_ringbuf_t pman_reserve_ringbuf_handle() {
	if(g_state.n_reserved_ringbuf_handles == g_state.rb_manager->ring_cnt) {
		return PMAN_INVALID_RING_BUFFER_HANDLE;
	}

	return g_state.ringbuf_handles[g_state.n_reserved_ringbuf_handles++];
}

static inline void *ringbuf__get_first_ring_event(struct ring *r, int pos) {
	int *len_ptr = NULL;
	int len = 0;

	/* If the consumer reaches the producer update the producer position to
	 * get the newly collected events.
	 */
	if(g_state.cons_pos[pos] == g_state.prod_pos[pos]) {
		// We try to increment the producer and continue. It is likely that the producer
		// has produced new events on this CPU and these events could have a timestamp
		// lowest than all the other events in the other buffers.
		g_state.prod_pos[pos] = smp_load_acquire(r->producer_pos);
		if(g_state.cons_pos[pos] == g_state.prod_pos[pos]) {
			return NULL;
		}
	}

	len_ptr = r->data + (g_state.cons_pos[pos] & r->mask);
	len = smp_load_acquire(len_ptr);

	/* The actual event is not yet committed */
	if(len & BPF_RINGBUF_BUSY_BIT) {
		return NULL;
	}

	/* the sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0) {
		/* Save the size of the event if we need to increment the consumer */
		g_state.last_event_size = roundup_len(len);
		return (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	} else {
		/* Discard the event kernel side and update the consumer position */
		g_state.cons_pos[pos] += roundup_len(len);
		smp_store_release(r->consumer_pos, g_state.cons_pos[pos]);
		return NULL;
	}
}

static void ringbuf__consume_first_event(struct ring_buffer *rb,
                                         struct ppm_evt_hdr **event_ptr,
                                         int16_t *buffer_id) {
	uint64_t min_ts = 0xffffffffffffffffLL;
	struct ppm_evt_hdr *tmp_pointer = NULL;
	int tmp_ring = -1;
	unsigned long tmp_cons_increment = 0;

	/* If the last consume operation was successful we can push the consumer position */
	if(g_state.last_ring_read != -1) {
		struct ring *r = rb->rings[g_state.last_ring_read];
		g_state.cons_pos[g_state.last_ring_read] += g_state.last_event_size;
		smp_store_release(r->consumer_pos, g_state.cons_pos[g_state.last_ring_read]);
	}

	R_D_MSG("\n-----------------------------\nIterate over all the buffers\n");
	for(uint16_t pos = 0; pos < rb->ring_cnt; pos++) {
		*event_ptr = ringbuf__get_first_ring_event(rb->rings[pos], pos);
		R_D_EVENT(*event_ptr, pos);

		/* if NULL search for events in another buffer */
		if(*event_ptr == NULL) {
			continue;
		}

		if((*event_ptr)->ts < min_ts) {
			min_ts = (*event_ptr)->ts;
			tmp_pointer = *event_ptr;
			tmp_ring = pos;
			tmp_cons_increment = g_state.last_event_size;
			R_D_MSG("Found new min with ts '%ld' on buffer %d\n", (*event_ptr)->ts, pos);
		}
	}

	*event_ptr = tmp_pointer;
	*buffer_id = tmp_ring;
	g_state.last_ring_read = tmp_ring;
	g_state.last_event_size = tmp_cons_increment;
	R_D_MSG("Send event -> ");
	R_D_EVENT(*event_ptr, tmp_ring);
}

/* Consume */
void pman_consume_first_event(void **event_ptr, int16_t *buffer_id) {
	ringbuf__consume_first_event(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, buffer_id);
}

static inline void *ringbuf__consume_first_ring_event(struct ring *r, int pos) {
	smp_store_release(r->consumer_pos, g_state.cons_pos[pos]);

	/* If the consumer reaches the producer update the producer position to
	 * get the newly collected events.
	 */
	if(g_state.cons_pos[pos] == g_state.prod_pos[pos]) {
		/* We try to increment the producer and continue. It is likely that the producer has
		 * produced new events on this ring. */
		g_state.prod_pos[pos] = smp_load_acquire(r->producer_pos);
		if(g_state.cons_pos[pos] == g_state.prod_pos[pos]) {
			return NULL;
		}
	}

	int *len_ptr = r->data + (g_state.cons_pos[pos] & r->mask);
	int len = smp_load_acquire(len_ptr);

	/* The actual event is not yet committed */
	if(len & BPF_RINGBUF_BUSY_BIT) {
		return NULL;
	}

	g_state.cons_pos[pos] += roundup_len(len);

	/* The sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0) {
		return (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	} else {
		/* Discard the event kernel side and update the consumer position */
		smp_store_release(r->consumer_pos, g_state.cons_pos[pos]);
		return NULL;
	}
}

void pman_consume_first_event_from_ringbuf(pman_ringbuf_t ringbuf_h, void **event_ptr) {
	/* The ring buffer handle represents the position of the ring buffer. */
	uint16_t pos = ringbuf_h;
	struct ring *r = g_state.rb_manager->rings[pos];
	*event_ptr = ringbuf__consume_first_ring_event(r, pos);
}
