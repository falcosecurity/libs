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

#ifndef _SCAP_BPF_H
#define _SCAP_BPF_H

#include <libscap/compat/bpf.h>
#include <libscap/compat/perf_event.h>
#include <libscap/scap_barrier.h>

struct perf_event_sample {
	struct perf_event_header header;
	uint32_t size;
	char data[];
};

struct perf_lost_sample {
	struct perf_event_header header;
	uint64_t id;
	uint64_t lost;
};

/* Return only the raw data of the event skipping the header and the size. */
static inline scap_evt *scap_bpf_evt_from_perf_sample(void *evt) {
	struct perf_event_sample *perf_evt = (struct perf_event_sample *)evt;
	ASSERT(perf_evt->header.type == PERF_RECORD_SAMPLE);
	return (scap_evt *)perf_evt->data;
}

static inline void scap_bpf_get_buf_pointers(scap_device *dev,
                                             uint64_t *phead,
                                             uint64_t *ptail,
                                             uint64_t *pread_size) {
	struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)dev->m_buffer;

	*phead = header->data_head;
	*ptail = header->data_tail;

	mem_barrier();

	uint64_t cons = *ptail % header->data_size;  // consumer position
	uint64_t prod = *phead % header->data_size;  // producer position

	/* `pread_size` is the number of bytes our consumer has to read to reach the producer.
	 * We want to obtain this information so we know how many bytes we can read.
	 *
	 * We have 2 possible cases:
	 * Where
	 * '*' = empty space
	 * '-' = data space
	 * 's' = total buffer size
	 * 'c' = consumer position
	 * 'p' = producer position
	 *
	 * 1. consumer > producer
	 *
	 *      p         c  s
	 * |----|*********|--|
	 *
	 *
	 * We want to obtain the data space so we do `s - c + p`.
	 *
	 * 2. consumer <= producer
	 *
	 *      c         p  s
	 * |****|---------|**|
	 *
	 * We want to obtain the data space so we do `p - c`.
	 */
	if(cons > prod) {
		*pread_size = header->data_size - cons + prod;
	} else {
		*pread_size = prod - cons;
	}
}

static inline int32_t scap_bpf_advance_to_evt(struct scap_device *dev,
                                              bool skip_current,
                                              char *cur_evt,
                                              char **next_evt,
                                              uint32_t *len) {
	void *base;
	void *begin;

	struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)dev->m_buffer;

	base = ((char *)header) + header->data_offset;

	/* if `skip_current` is true it means that we need to increment the position
	 * and this `begin` points to an event that we have already read. If `false`
	 * `begin` points to an event that we still have to read.
	 */
	begin = cur_evt;

	while(*len) {
		struct perf_event_header *e = begin;

		ASSERT(*len >= sizeof(*e));
		ASSERT(*len >= e->size);
		if(e->type == PERF_RECORD_SAMPLE) {
#ifdef _DEBUG
			struct perf_event_sample *sample = (struct perf_event_sample *)e;
#endif
			ASSERT(*len >= sizeof(*sample));
			ASSERT(*len >= sample->size);
			ASSERT(e->size == sizeof(*e) + sizeof(sample->size) + sample->size);
			ASSERT(((scap_evt *)sample->data)->len <= sample->size);

			if(skip_current) {
				skip_current = false;
			} else {
				*next_evt = (char *)e;
				break;
			}
		} else if(e->type != PERF_RECORD_LOST) {
			printf("Unknown event type=%d size=%d\n", e->type, e->size);
			ASSERT(false);
		}

		/* Move the pointer inside the block to the next event */
		if(begin + e->size > base + header->data_size) {
			begin = begin + e->size - header->data_size;
		} else if(begin + e->size == base + header->data_size) {
			begin = base;
		} else {
			begin += e->size;
		}

		/* Decrease the size of the block since we have just read an event */
		*len -= e->size;
	}

	return SCAP_SUCCESS;
}

/* This helper increments the consumer position */
static inline void scap_bpf_advance_tail(struct scap_device *dev) {
	struct perf_event_mmap_page *header;

	header = (struct perf_event_mmap_page *)dev->m_buffer;

	mem_barrier();

	ASSERT(dev->m_lastreadsize > 0);
	/* `header->data_tail` is the consumer position. */
	header->data_tail += dev->m_lastreadsize;
	dev->m_lastreadsize = 0;
}

static inline int32_t scap_bpf_readbuf(struct scap_device *dev, char **buf, uint32_t *len) {
	struct perf_event_mmap_page *header;
	uint64_t tail;
	uint64_t head;
	uint64_t read_size;
	char *p;

	header = (struct perf_event_mmap_page *)dev->m_buffer;

	ASSERT(dev->m_lastreadsize == 0);
	scap_bpf_get_buf_pointers(dev, &head, &tail, &read_size);

	/* This contains the dimension of the block and it will be used to increment
	 * the consumer position in `scap_bpf_advance_tail`.
	 */
	dev->m_lastreadsize = read_size;
	/* position of the consumer */
	p = ((char *)header) + header->data_offset + tail % header->data_size;
	*len = read_size;

	return scap_bpf_advance_to_evt(dev, false, p, buf, len);
}

#endif
