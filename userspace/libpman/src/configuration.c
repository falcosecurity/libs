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

#include "state.h"
#include <sys/resource.h>

static int libbpf_print(enum libbpf_print_level level, const char* format, va_list args)
{
	enum falcosecurity_log_severity sev;
	switch(level)
	{
	case LIBBPF_WARN:
		sev = FALCOSECURITY_LOG_SEV_WARNING;
		break;
	case LIBBPF_INFO:
		sev = FALCOSECURITY_LOG_SEV_INFO;
		break;
	case LIBBPF_DEBUG:
		sev = FALCOSECURITY_LOG_SEV_DEBUG;
		break;
	default:
		return -EINVAL;
	}

	if(g_state.log_fn == NULL)
		return vfprintf(stderr, format, args);

	char buf[4096];
	int rc = vsnprintf(buf, sizeof(buf), format, args);
	if(rc < 0)
		return rc;

	// don't need a component name for libbpf, it will prepend "libbpf: " to logs for us
	g_state.log_fn(NULL, buf, sev);
	return rc;
}

void pman_clear_state()
{
	g_state.skel = NULL;
	g_state.rb_manager = NULL;
	g_state.n_possible_cpus = 0;
	g_state.n_interesting_cpus = 0;
	g_state.allocate_online_only = false;
	g_state.n_required_buffers = 0;
	g_state.cpus_for_each_buffer = 0;
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = NULL;
	g_state.prod_pos = NULL;
	g_state.inner_ringbuf_map_fd = 0;
	g_state.buffer_bytes_dim = 0;
	g_state.last_ring_read = -1;
	g_state.last_event_size = 0;
	g_state.n_attached_progs = 0;
	g_state.stats = NULL;
	g_state.log_fn = NULL;
}

int pman_init_state(falcosecurity_log_fn log_fn, unsigned long buf_bytes_dim, uint16_t cpus_for_each_buffer,
		    bool allocate_online_only)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];

	/* `LIBBPF_STRICT_ALL` turns on all supported strict features
	 * of libbpf to simulate libbpf v1.0 behavior.
	 * `libbpf_set_strict_mode` returns always 0.
	 */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set libbpf logging. */
	g_state.log_fn = log_fn;
	libbpf_set_print(libbpf_print);

	/* Bump rlimit in any case. We need to do that because some kernels backport
	 * just a few features but not all the necessary ones.
	 * Falco issue: https://github.com/falcosecurity/falco/issues/2626
	 * Libbpf issue: https://lore.kernel.org/netdev/20220610112648.29695-1-quentin@isovalent.com/T/
	 */
	struct rlimit rl = {0};
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;
	if(setrlimit(RLIMIT_MEMLOCK, &rl))
	{
		pman_print_error("unable to bump RLIMIT_MEMLOCK to RLIM_INFINITY");
		return -1;
	}

	/* Set the available number of CPUs inside the internal state. */
	g_state.n_possible_cpus = libbpf_num_possible_cpus();
	if(g_state.n_possible_cpus <= 0)
	{
		pman_print_error("no available cpus");
		return -1;
	}

	g_state.allocate_online_only = allocate_online_only;

	if(g_state.allocate_online_only)
	{
		ssize_t online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if(online_cpus != -1)
		{
			/* We will allocate buffers only for online CPUs */
			g_state.n_interesting_cpus = online_cpus;
		}
		else
		{
			/* Fallback to all available CPU even if the `allocate_online_only` flag is set to `true` */
			g_state.n_interesting_cpus = g_state.n_possible_cpus;
		}
	}
	else
	{
		/* We will allocate buffers only for all available CPUs */
		g_state.n_interesting_cpus = g_state.n_possible_cpus;
	}

	/* We are requiring a buffer every `cpus_for_each_buffer` CPUs,
	 * but `cpus_for_each_buffer` is greater than our possible CPU number!
	 */
	if(cpus_for_each_buffer > g_state.n_interesting_cpus)
	{
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN,
			 "buffer every '%d' CPUs, but '%d' is greater than our interesting CPU number (%d)!",
			 cpus_for_each_buffer, cpus_for_each_buffer, g_state.n_interesting_cpus);
		pman_print_error((const char*)error_message);
		return -1;
	}

	/* `0` is a special value that means a single ring buffer shared between all the CPUs */
	if(cpus_for_each_buffer == 0)
	{
		/* We want a single ring buffer so 1 ring buffer for all the interesting CPUs we have */
		g_state.cpus_for_each_buffer = g_state.n_interesting_cpus;
	}
	else
	{
		g_state.cpus_for_each_buffer = cpus_for_each_buffer;
	}

	/* Set the number of ring buffers we need */
	g_state.n_required_buffers = g_state.n_interesting_cpus / g_state.cpus_for_each_buffer;
	/* If we have some remaining CPUs it means that we need another buffer */
	if((g_state.n_interesting_cpus % g_state.cpus_for_each_buffer) != 0)
	{
		g_state.n_required_buffers++;
	}
	/* Set the dimension of a single ring buffer */
	g_state.buffer_bytes_dim = buf_bytes_dim;

	/* These will be used during the ring buffer consumption phase. */
	g_state.last_ring_read = -1;
	g_state.last_event_size = 0;
	return 0;
}

int pman_get_required_buffers() { return g_state.n_required_buffers; }

/*
 * Probe the kernel for required dependencies, ring buffer maps and tracing
 * progs needs to be supported.
 */
bool pman_check_support()
{
	bool res;

	res = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL) > 0;
	if(!res)
	{
		pman_print_error("ring buffer map type is not supported");
		return res;
	}

	res = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL) > 0;
	if(!res)
	{
		pman_print_error("tracing program type is not supported");
		return res;
	}

	/* Probe result depends on the success of map creation, no additional
	 * check required for unprivileged users
	 */

	return res;
}
