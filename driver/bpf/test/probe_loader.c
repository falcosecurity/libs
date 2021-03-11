/*
Copyright (C) 2021 The Falco Authors.

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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include "probe_loader.h"

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

int do_test_single_filler(const char *filler_name, struct sys_exit_args ctx, enum ppm_event_type event_type, char *scratch)
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

	obj = bpf_object__open(g_probe_path);
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

	struct tail_context tail_ctx;
	tail_ctx.evt_type = event_type;
	tail_ctx.curarg = 0;
	tail_ctx.curoff = 0;
	tail_ctx.len = 0;
	tail_ctx.prev_res = 0;

	struct sysdig_bpf_per_cpu_state state;
	state.tail_ctx = tail_ctx;

	err = bpf_map_update_elem(local_state_map, &cpu, &state, BPF_ANY);
	if(err != 0)
	{
		fprintf(stderr, "ERROR: could not update local_state_map\n");
		bpf_object__close(obj);
		return err;
	}

	event_info_map = bpf_object__find_map_fd_by_name(obj, "event_info_table");
	err = bpf_map_update_elem(event_info_map, &event_type, &g_event_info[event_type], BPF_ANY);
	if(err != 0)
	{
		fprintf(stderr, "ERROR: could not update event_info_table\n");
		bpf_object__close(obj);
		return err;
	}

	prog = bpf_object__find_program_by_name(obj, filler_name);

	prog_fd = bpf_program__fd(prog);

	tattr.prog_fd = prog_fd;
	tattr.ctx_in = &ctx;
	tattr.ctx_size_in = sizeof(struct sys_exit_args);

	err = bpf_prog_test_run_xattr(&tattr);

	get_scratch(obj, cpu, scratch);

	return err;
}
