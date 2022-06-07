#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <struct_definitions.h> // contains definition used in the skeleton
#include <bpf_probe.skel.h>
#include <unistd.h>

#define MAX_ERROR_MESSAGE_LEN 100

struct internal_state
{
	struct bpf_probe* skel;		/* bpf skeleton with all programs and maps. */
	struct ring_buffer* rb_manager; /* ring_buffer manager with all per-CPU ringbufs. */
	int16_t n_cpus;			/* number of system available CPUs. */
	int ringbuf_pos;		/* actual ringbuf we are considering. */
	unsigned long* cons_pos;	/* every ringbuf has a consumer position. */
	unsigned long* prod_pos;	/* every ringbuf has a producer position. */
	int32_t inner_ringbuf_map_fd;	/* inner map used to configure the ringbuf array before loading phase. */
};

extern struct internal_state g_state;

extern void libpman__print_error(const char* error_message);
