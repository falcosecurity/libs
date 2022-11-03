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

#pragma once

#include "state.h"
#include <linux/bpf.h>

/* Taken from libbpf: /src/ringbuf.c */
struct ring
{
	ring_buffer_sample_fn sample_cb;
	void *ctx;
	void *data;
	unsigned long *consumer_pos;
	unsigned long *producer_pos;
	unsigned long mask;
	int map_fd;
};

struct ring_buffer
{
	struct epoll_event *events;
	struct ring *rings;
	size_t page_size;
	int epoll_fd;
	int ring_cnt;
};

/* This is done to write on multiples of 8 bytes. */
static inline int roundup_len(uint32_t len)
{
	/* clear out top 2 bits (discard and busy, if set) */
	len <<= 2;
	len >>= 2;
	/* add length prefix */
	len += BPF_RINGBUF_HDR_SZ;
	/* round up to 8 byte alignment */
	return (len + 7) / 8 * 8;
}

/* Taken from libbpf: `include/linux/compiler.h` */

#define READ_ONCE(x) (*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)

#define barrier() asm volatile("" :: \
				       : "memory")

#define smp_store_release(p, v)    \
	do                         \
	{                          \
		barrier();         \
		WRITE_ONCE(*p, v); \
	} while(0)

#define smp_load_acquire(p)                      \
	({                                       \
		typeof(*p) ___p = READ_ONCE(*p); \
		barrier();                       \
		___p;                            \
	})
