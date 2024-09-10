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
#include <driver/feature_gates.h>

int pman_open_probe() {
	g_state.skel = bpf_probe__open();
	if(!g_state.skel) {
		pman_print_error("failed to open BPF skeleton");
		return errno;
	}
	return 0;
}

static void pman_save_attached_progs() {
	g_state.attached_progs_fds[0] = bpf_program__fd(g_state.skel->progs.sys_enter);
	g_state.attached_progs_fds[1] = bpf_program__fd(g_state.skel->progs.sys_exit);
	g_state.attached_progs_fds[2] = bpf_program__fd(g_state.skel->progs.sched_proc_exit);
	g_state.attached_progs_fds[3] = bpf_program__fd(g_state.skel->progs.sched_switch);
#ifdef CAPTURE_SCHED_PROC_EXEC
	g_state.attached_progs_fds[4] = bpf_program__fd(g_state.skel->progs.sched_p_exec);
#endif
#ifdef CAPTURE_SCHED_PROC_FORK
	g_state.attached_progs_fds[5] = bpf_program__fd(g_state.skel->progs.sched_p_fork);
#endif
#ifdef CAPTURE_PAGE_FAULTS
	g_state.attached_progs_fds[6] = bpf_program__fd(g_state.skel->progs.pf_user);
	g_state.attached_progs_fds[7] = bpf_program__fd(g_state.skel->progs.pf_kernel);
#endif
	g_state.attached_progs_fds[8] = bpf_program__fd(g_state.skel->progs.signal_deliver);
}

int pman_load_probe() {
	if(bpf_probe__load(g_state.skel)) {
		pman_print_error("failed to load BPF object");
		return errno;
	}
	pman_save_attached_progs();
	// Programs are loaded so we passed the verifier we can free the 16 MB
	if(g_state.log_buf) {
		free(g_state.log_buf);
		g_state.log_buf = NULL;
		g_state.log_buf_size = 0;
	}
	return 0;
}

void pman_close_probe() {
	if(g_state.stats) {
		free(g_state.stats);
		g_state.stats = NULL;
	}

	if(g_state.cons_pos) {
		free(g_state.cons_pos);
		g_state.cons_pos = NULL;
	}

	if(g_state.prod_pos) {
		free(g_state.prod_pos);
		g_state.prod_pos = NULL;
	}

	if(g_state.skel) {
		bpf_probe__detach(g_state.skel);
		bpf_probe__destroy(g_state.skel);
	}

	if(g_state.rb_manager) {
		ring_buffer__free(g_state.rb_manager);
	}
}
