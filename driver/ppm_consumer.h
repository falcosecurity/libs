/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef CONSUMER_H_
#define CONSUMER_H_

#include <linux/types.h>

struct ppm_consumer_t {
	unsigned int id; // numeric id for the consumer (ie: registration index)
	struct task_struct *consumer_id;
#ifdef __percpu
	struct ppm_ring_buffer_context __percpu *ring_buffers;
#else
	struct ppm_ring_buffer_context *ring_buffers;
#endif
	u32 snaplen;
	u32 sampling_ratio;
	bool do_dynamic_snaplen;
	u32 sampling_interval;
	int is_dropping;
	int dropping_mode;
	bool drop_failed;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	struct list_head node;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
	unsigned long buffer_bytes_dim; /* Every consumer will have its per-CPU buffer dim in bytes. */
	DECLARE_BITMAP(syscalls_mask, SYSCALL_TABLE_SIZE);
	u32 tracepoints_attached;
};

typedef struct ppm_consumer_t ppm_consumer_t;

#endif // CONSUMER_H_
