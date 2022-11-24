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

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "../../ringbuffer/devset.h"

#define UDIG_RING_SM_FNAME "udig_buf"
#define UDIG_RING_DESCS_SM_FNAME "udig_descs"
#define UDIG_RING_SIZE (8 * 1024 * 1024)

struct scap;

struct udig_consumer_t
{
	uint32_t snaplen;
	uint32_t sampling_ratio;
	bool do_dynamic_snaplen;
	uint32_t sampling_interval;
	int is_dropping;
	int dropping_mode;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	uint16_t fullcapture_port_range_start;
	uint16_t fullcapture_port_range_end;
	uint16_t statsd_port;
};

struct udig_ring_buffer_status
{
	volatile uint64_t m_buffer_lock;
	volatile int m_initialized;
	volatile int m_capturing_pid;
	volatile int m_stopped;
	volatile struct timespec m_last_print_time;
	struct udig_consumer_t m_consumer;
};

struct udig_engine
{
	struct scap_device_set m_dev_set;

	char* m_lasterr;
	bool m_udig_capturing;
};
