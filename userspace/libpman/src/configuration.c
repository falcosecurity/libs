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

#include "state.h"

static int setup_libbpf_print_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	if(level == LIBBPF_WARN)
	{
		return vfprintf(stderr, format, args);
	}
	return 0;
}

static void setup_libbpf_logging(bool verbosity)
{
	if(verbosity)
	{
		/* `libbpf_set_print` returns the old log function. */
		libbpf_set_print(setup_libbpf_print_verbose);
	}
	else
	{
		libbpf_set_print(setup_libbpf_print_no_verbose);
	}
}

int pman_init_state(bool verbosity, unsigned long buf_bytes_dim)
{

	/* `LIBBPF_STRICT_ALL` turns on all supported strict features
	 * of libbpf to simulate libbpf v1.0 behavior.
	 * `libbpf_set_strict_mode` returns always 0.
	 */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set libbpf verbosity. */
	setup_libbpf_logging(verbosity);

	/* Set the available number of CPUs inside the internal state. */
	g_state.n_cpus = libbpf_num_possible_cpus();
	if(g_state.n_cpus <= 0)
	{
		pman_print_error("no available cpus");
		return -1;
	}

	/* Set the dimension of a single per-CPU ring buffer. */
	g_state.buffer_bytes_dim = buf_bytes_dim;
	return 0;
}

int pman_get_cpus_number()
{
	return g_state.n_cpus;
}
