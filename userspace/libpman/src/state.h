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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <shared_definitions/struct_definitions.h>
#include <bpf_probe.skel.h>
#include <unistd.h>

#define MAX_ERROR_MESSAGE_LEN 100

struct internal_state
{
	struct bpf_probe* skel;		/* bpf skeleton with all programs and maps. */
	struct ring_buffer* rb_manager; /* ring_buffer manager with all per-CPU ringbufs. */
	int16_t n_possible_cpus;			/* number of possible system CPUs (online and not). */
	int16_t n_interesting_cpus;			/* according to userspace configuration we can consider only online CPUs or all available CPUs. */
	bool allocate_online_only;      /* If true we allocate ring buffers only for online CPUs */
	uint32_t n_required_buffers;	/* number of ring buffers we need to allocate */
	uint16_t cpus_for_each_buffer;	/* Users want a ring buffer every `cpus_for_each_buffer` CPUs */
	int ringbuf_pos;		/* actual ringbuf we are considering. */
	unsigned long* cons_pos;	/* every ringbuf has a consumer position. */
	unsigned long* prod_pos;	/* every ringbuf has a producer position. */
	int32_t inner_ringbuf_map_fd;	/* inner map used to configure the ringbuf array before loading phase. */
	unsigned long buffer_bytes_dim; /* dimension of a single per-CPU ringbuffer in bytes. */
	int last_ring_read;		/* Last ring from which we have correctly read an event. Could be `-1` if there were no successful reads. */
	unsigned long last_event_size;	/* Last event correctly read. Could be `0` if there were no successful reads. */
};

extern struct internal_state g_state;

extern void pman_print_error(const char* error_message);
