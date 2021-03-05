/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/perf_event.h>

#include "test_fillers.h"

#define _STRINGIFY_PASS(x) #x
#define STRINGIFY(x) _STRINGIFY_PASS(x)

void set_rlimit_infinity(void)
{
	struct rlimit rinf = {RLIM_INFINITY, RLIM_INFINITY};

	setrlimit(RLIMIT_MEMLOCK, &rinf);
}

int do_test_single_filler(__u32 *retval, const char *filler_name, struct filler_data data)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object_load_attr load_attr = {};
	struct bpf_prog_test_run_attr tattr = {};
	int prog_fd;
	int err;

	obj = bpf_object__open(STRINGIFY(PROBE_PATH));
	load_attr.obj = obj;

	if(libbpf_get_error(obj))
	{
		debug_fprintf(stderr, "error opening the bpf object\n");
		return EXIT_FAILURE;
	}
	uint32_t n_cpu = sysconf(_SC_NPROCESSORS_CONF);

	set_rlimit_infinity();

	bpf_object__for_each_map(map, obj)
	{
		const char *map_name = bpf_map__name(map);
		if(strcmp(map_name, "frame_scratch_map") == 0 ||
		   strcmp(map_name, "local_state_map") == 0 ||
		   strcmp(map_name, "perf_map") == 0 ||
		   strcmp(map_name, "tmp_scratch_map") == 0)
		{
			bpf_map__set_max_entries(map, n_cpu);
		}
		debug_fprintf(stdout, "map found: %s\n", bpf_map__name(map));
	}

	if(bpf_object__load_xattr(&load_attr))
	{
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		bpf_object__close(obj);
		return -1;
	}

	prog = bpf_object__find_program_by_name(obj, filler_name);

	prog_fd = bpf_program__fd(prog);

	tattr.prog_fd = prog_fd;
	tattr.ctx_in = &data;
	tattr.ctx_size_in = sizeof(data);

	err = bpf_prog_test_run_xattr(&tattr);
	*retval = tattr.retval;
	return err;
}
