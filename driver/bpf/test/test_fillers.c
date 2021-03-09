/* SPDX-License-Identifier: GPL-2.0 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include "test_fillers.h"

#define _STRINGIFY_PASS(x) #x
#define STRINGIFY(x) _STRINGIFY_PASS(x)

void set_rlimit_infinity(void)
{
	struct rlimit rinf = {RLIM_INFINITY, RLIM_INFINITY};

	setrlimit(RLIMIT_MEMLOCK, &rinf);
}

int get_scratch(struct bpf_object *obj, unsigned int cpu, char *scratch)
{
	int frame_scratch_map;
	frame_scratch_map = bpf_object__find_map_fd_by_name(obj, "frame_scratch_map");
	return bpf_map_lookup_elem(frame_scratch_map, &cpu, scratch);
}

int do_test_single_filler(const char *filler_name, struct filler_data data, char *scratch)
{
	unsigned int cpu;
	unsigned int numa;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object_load_attr load_attr = {};
	struct bpf_prog_test_run_attr tattr = {};
	int prog_fd;
	int err;
	int local_state_map;
	int event_info_map;
	struct bpf_object *obj;

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
	local_state_map = bpf_object__find_map_fd_by_name(obj, "local_state_map");

	getcpu(&cpu, &numa);

	err = bpf_map_update_elem(local_state_map, &cpu, data.state, BPF_ANY);
	if(err != 0)
	{
		fprintf(stderr, "ERROR: could not update local_state_map\n");
		bpf_object__close(obj);
		return err;
	}

	event_info_map = bpf_object__find_map_fd_by_name(obj, "event_info_table");
	err = bpf_map_update_elem(event_info_map, &data.state->tail_ctx.evt_type, &g_event_info[data.state->tail_ctx.evt_type], BPF_ANY);
	if(err != 0)
	{
		fprintf(stderr, "ERROR: could not update event_info_table\n");
		bpf_object__close(obj);
		return err;
	}

	prog = bpf_object__find_program_by_name(obj, filler_name);

	prog_fd = bpf_program__fd(prog);

	tattr.prog_fd = prog_fd;
	tattr.ctx_in = data.ctx;
	tattr.ctx_size_in = sizeof(struct sys_exit_args);

	err = bpf_prog_test_run_xattr(&tattr);

	get_scratch(obj, cpu, scratch);

	int nparams = g_event_info[data.state->tail_ctx.evt_type].nparams;
	int header_offset = sizeof(struct ppm_evt_hdr) + sizeof(__u16) * nparams;

	return err;
}
