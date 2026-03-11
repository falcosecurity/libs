// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include "support_probing.h"
#include "state.h"

#ifdef BPF_ITERATOR_SUPPORT

static int init_iter_ctx(struct iter_support_probing_ctx *ctx) {
	struct bpf_probe *probe = bpf_probe__open();
	if(!probe) {
		pman_print_errorf("failed to open BPF probe for iter support probing");
		return -1;
	}

	ctx->probe = probe;
	ctx->inner_ringbuf_map_fd = -1;
	return 0;
}

static void destroy_iter_ctx(struct iter_support_probing_ctx *ctx) {
	if(ctx->probe) {
		bpf_probe__destroy(ctx->probe);
		ctx->probe = NULL;
	}

	if(ctx->inner_ringbuf_map_fd != -1) {
		close(ctx->inner_ringbuf_map_fd);
		ctx->inner_ringbuf_map_fd = -1;
	}
}

static void disable_all_progs(struct bpf_probe *probe) {
	// Disable ALL programs.
	struct bpf_program *cur_prog;
	bpf_object__for_each_program(cur_prog, probe->obj) {
		bpf_program__set_autoload(cur_prog, false);
	}

	// Re-enable the ones statically linked to prog array maps in eBPF code or loading will fail
	// (note: disabling creation of these maps doesn't work in these cases).
	bpf_program__set_autoload(probe->progs.t_hotplug, true);
	bpf_program__set_autoload(probe->progs.t_drop_e, true);
	bpf_program__set_autoload(probe->progs.t_drop_x, true);
#ifdef CAPTURE_SCHED_PROC_FORK
	bpf_program__set_autoload(probe->progs.t1_sched_p_fork, true);
	bpf_program__set_autoload(probe->progs.t2_sched_p_fork, true);
#endif
	bpf_program__set_autoload(probe->progs.t1_sched_p_exec, true);
	bpf_program__set_autoload(probe->progs.t2_sched_p_exec, true);
}

int iter_support_probing__probe(const char *prog_name) {
	struct iter_support_probing_ctx ctx;

	int err = init_iter_ctx(&ctx);
	if(err) {
		return -1;
	}

	// Retrieve the program we are probing support for.
	struct bpf_program *prog_to_test = bpf_object__find_program_by_name(ctx.probe->obj, prog_name);
	if(!prog_to_test) {
		pman_print_errorf("failed to find BPF program '%s' to test in BPF probe", prog_name);
		destroy_iter_ctx(&ctx);
		return -1;
	}

	// Disable all programs except the one we are probing support for.
	disable_all_progs(ctx.probe);
	bpf_program__set_autoload(prog_to_test, true);

	// Initialize every required piece before trying to load the probe.
	err = iter_support_probing__prepare_ringbuf_array_before_loading(&ctx);
	err = err ?: iter_support_probing__prepare_maps_before_loading(&ctx);
	if(err) {
		pman_print_errorf("encountered error before loading BPF probe for iter support probing");
		destroy_iter_ctx(&ctx);
		return -1;
	}

	err = bpf_probe__load(ctx.probe);
	destroy_iter_ctx(&ctx);
	return err;
}

#endif  // BPF_ITERATOR_SUPPORT
