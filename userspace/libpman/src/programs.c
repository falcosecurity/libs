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

#include "state.h"
#include "events_prog_table.h"
#include <driver/feature_gates.h>
#include <libpman.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

/*=============================== ATTACH PROGRAMS ===============================*/

int attach_syscall_exit_dispatcher() {
	/* The program is already attached. */
	if(g_state.skel->links.sys_exit != NULL) {
		return 0;
	}

	g_state.skel->links.sys_exit = bpf_program__attach(g_state.skel->progs.sys_exit);
	if(!g_state.skel->links.sys_exit) {
		log_errorf("failed to attach the 'sys_exit' program");
		return errno;
	}
	return 0;
}

int attach_sched_proc_exit() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_proc_exit != NULL) {
		return 0;
	}

	g_state.skel->links.sched_proc_exit = bpf_program__attach(g_state.skel->progs.sched_proc_exit);
	if(!g_state.skel->links.sched_proc_exit) {
		log_errorf("failed to attach the 'sched_proc_exit' program");
		return errno;
	}
	return 0;
}

int attach_sched_switch() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_switch != NULL) {
		return 0;
	}

	g_state.skel->links.sched_switch = bpf_program__attach(g_state.skel->progs.sched_switch);
	if(!g_state.skel->links.sched_switch) {
		log_errorf("failed to attach the 'sched_switch' program");
		return errno;
	}
	return 0;
}

int attach_sched_proc_exec() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_exec != NULL) {
		return 0;
	}

	g_state.skel->links.sched_p_exec = bpf_program__attach(g_state.skel->progs.sched_p_exec);
	if(!g_state.skel->links.sched_p_exec) {
		log_errorf("failed to attach the 'sched_proc_exec' program");
		return errno;
	}
	return 0;
}

int attach_sched_proc_fork() {
#ifdef CAPTURE_SCHED_PROC_FORK
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_fork != NULL) {
		return 0;
	}

	g_state.skel->links.sched_p_fork = bpf_program__attach(g_state.skel->progs.sched_p_fork);
	if(!g_state.skel->links.sched_p_fork) {
		log_errorf("failed to attach the 'sched_proc_fork' program");
		return errno;
	}
#endif
	return 0;
}

int attach_page_fault_user() {
#ifdef CAPTURE_PAGE_FAULTS
	/* The program is already attached. */
	if(g_state.skel->links.pf_user != NULL) {
		return 0;
	}

	g_state.skel->links.pf_user = bpf_program__attach(g_state.skel->progs.pf_user);
	if(!g_state.skel->links.pf_user) {
		log_errorf("failed to attach the 'pf_user' program");
		return errno;
	}
#endif
	return 0;
}

int attach_page_fault_kernel() {
#ifdef CAPTURE_PAGE_FAULTS
	/* The program is already attached. */
	if(g_state.skel->links.pf_kernel != NULL) {
		return 0;
	}

	g_state.skel->links.pf_kernel = bpf_program__attach(g_state.skel->progs.pf_kernel);
	if(!g_state.skel->links.pf_kernel) {
		log_errorf("failed to attach the 'pf_kernel' program");
		return errno;
	}
#endif
	return 0;
}

int attach_signal_deliver() {
	/* The program is already attached. */
	if(g_state.skel->links.signal_deliver != NULL) {
		return 0;
	}

	g_state.skel->links.signal_deliver = bpf_program__attach(g_state.skel->progs.signal_deliver);
	if(!g_state.skel->links.signal_deliver) {
		log_errorf("failed to attach the 'signal_deliver' program");
		return errno;
	}
	return 0;
}

/* Some kernels run a BPF program on a syscall tracepoint that reads user memory, such as the
 * `open` family, only if a perf event of the tracepoint is active on the current CPU. libbpf
 * attaches a tracepoint program through one perf event on CPU 0, so on these kernels the program
 * runs only for system calls on CPU 0. `pman_load_probe()` finds these kernels and sets
 * `g_state.ttm_needs_perf_events`.
 *
 * On these kernels, libpman opens one counting perf event of the tracepoint of each 64-bit TOCTOU
 * mitigation program on each CPU. Nothing reads the events. The programs return 0, so the kernel
 * records nothing for the events. A CPU that comes online after the attachment has no event.
 */
static int* ttm_perf_event_fds[TTM_MAX];

// Return the id of the tracepoint `tp_name` (e.g. `syscalls/sys_enter_openat`), or `-errno`.
static int read_tracepoint_id(const char* tp_name) {
	static const char* const tracefs_roots[] = {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"};
	int err = ENOENT;
	for(size_t i = 0; i < sizeof(tracefs_roots) / sizeof(tracefs_roots[0]); i++) {
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/events/%s/id", tracefs_roots[i], tp_name);
		FILE* f = fopen(path, "re");
		if(!f) {
			err = errno;
			continue;
		}
		int id = -1;
		const int matched = fscanf(f, "%d", &id);
		fclose(f);
		return matched == 1 && id >= 0 ? id : -EINVAL;
	}
	return -err;
}

static void close_toctou_perf_events_of(enum ttm_sc_code sc) {
	int* fds = ttm_perf_event_fds[sc];
	if(!fds) {
		return;
	}
	for(int cpu = 0; cpu < g_state.n_possible_cpus; cpu++) {
		if(fds[cpu] >= 0) {
			close(fds[cpu]);
		}
	}
	free(fds);
	ttm_perf_event_fds[sc] = NULL;
}

void close_toctou_perf_events() {
	for(int sc = 0; sc < TTM_MAX; sc++) {
		close_toctou_perf_events_of(sc);
	}
}

// Open one perf event of the tracepoint of `prog` on each CPU, if the kernel needs them.
// Return `0` on success, `errno` in case of error.
static int open_toctou_perf_events(const struct bpf_program* prog, enum ttm_sc_code sc) {
	// The `connect` tracepoint reads no user memory, so its program runs on every CPU.
	if(!g_state.ttm_needs_perf_events || sc == TTM_CONNECT || ttm_perf_event_fds[sc]) {
		return 0;
	}

	static const char tracepoint_prefix[] = "tracepoint/";
	const char* section = bpf_program__section_name(prog);
	if(strncmp(section, tracepoint_prefix, sizeof(tracepoint_prefix) - 1) != 0) {
		return 0;
	}
	const char* tp_name = section + sizeof(tracepoint_prefix) - 1;

	const int id = read_tracepoint_id(tp_name);
	if(id == -ENOENT) {
		// The attachment of the program reports a missing tracepoint.
		return 0;
	}
	if(id < 0) {
		errno = -id;
		log_errorf("cannot read the id of the '%s' tracepoint", tp_name);
		return -id;
	}

	int* fds = calloc(g_state.n_possible_cpus, sizeof(*fds));
	if(!fds) {
		log_errorf("cannot allocate the perf events of the '%s' tracepoint", tp_name);
		return ENOMEM;
	}
	for(int cpu = 0; cpu < g_state.n_possible_cpus; cpu++) {
		fds[cpu] = -1;
	}
	ttm_perf_event_fds[sc] = fds;

	struct perf_event_attr attr = {
	        .type = PERF_TYPE_TRACEPOINT,
	        .size = sizeof(attr),
	        .config = (uint64_t)id,
	};
	for(int cpu = 0; cpu < g_state.n_possible_cpus; cpu++) {
		fds[cpu] = (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		// ENODEV: the CPU is offline.
		if(fds[cpu] < 0 && errno != ENODEV) {
			const int err = errno;
			close_toctou_perf_events_of(sc);
			errno = err;
			log_errorf("cannot open a perf event of the '%s' tracepoint on CPU %d", tp_name, cpu);
			return err;
		}
	}
	return 0;
}

static int attach_64bit_toctou_prog(const struct bpf_program* prog,
                                    struct bpf_link** prog_link,
                                    enum ttm_sc_code sc) {
	if(*prog_link != NULL) {
		return 0;
	}
	// Open the perf events first: reading the tracepoint id after the attachment of the `openat`
	// program would send an `openat` enter event.
	const int res = open_toctou_perf_events(prog, sc);
	if(res) {
		return res;
	}
	*prog_link = bpf_program__attach(prog);
	if(!*prog_link) {
		const int err = errno;
		close_toctou_perf_events_of(sc);
		return err;
	}
	return 0;
}

static int attach_ia32_toctou_prog(const struct bpf_program* ia32_compat_prog,
                                   const struct bpf_program* ia32_prog,
                                   struct bpf_link** ia32_compat_prog_link,
                                   struct bpf_link** ia32_prog_link) {
	if(*ia32_compat_prog_link != NULL || *ia32_prog_link != NULL) {
		return 0;
	}

	// For ia-32 TOCTOU mitigation, the compat version takes precedence.
	if(bpf_program__fd(ia32_compat_prog) >= 0) {
		*ia32_compat_prog_link = bpf_program__attach(ia32_compat_prog);
		if(!*ia32_compat_prog_link) {
			return errno;
		}
	} else if(bpf_program__fd(ia32_prog) >= 0) {
		*ia32_prog_link = bpf_program__attach(ia32_prog);
		if(!*ia32_prog_link) {
			return errno;
		}
	}
	return 0;
}

int attach_connect_toctou_mitigation_progs() {
	const int res = attach_64bit_toctou_prog(g_state.skel->progs.connect_e,
	                                         &g_state.skel->links.connect_e,
	                                         TTM_CONNECT);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_connect_e,
	                               g_state.skel->progs.ia32_connect_e,
	                               &g_state.skel->links.ia32_compat_connect_e,
	                               &g_state.skel->links.ia32_connect_e);
}

int attach_creat_toctou_mitigation_progs() {
	const int res = attach_64bit_toctou_prog(g_state.skel->progs.creat_e,
	                                         &g_state.skel->links.creat_e,
	                                         TTM_CREAT);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_creat_e,
	                               g_state.skel->progs.ia32_creat_e,
	                               &g_state.skel->links.ia32_compat_creat_e,
	                               &g_state.skel->links.ia32_creat_e);
}

int attach_open_toctou_mitigation_progs() {
	const int res = attach_64bit_toctou_prog(g_state.skel->progs.open_e,
	                                         &g_state.skel->links.open_e,
	                                         TTM_OPEN);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_open_e,
	                               g_state.skel->progs.ia32_open_e,
	                               &g_state.skel->links.ia32_compat_open_e,
	                               &g_state.skel->links.ia32_open_e);
}

int attach_openat_toctou_mitigation_progs() {
	// Attach ia-32 programs before 64 bit program, otherwise the 64 bit program will generate
	// events for the ia-32 programs attachment attempts.
	const int res = attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_openat_e,
	                                        g_state.skel->progs.ia32_openat_e,
	                                        &g_state.skel->links.ia32_compat_openat_e,
	                                        &g_state.skel->links.ia32_openat_e);
	if(res) {
		return res;
	}
	return attach_64bit_toctou_prog(g_state.skel->progs.openat_e,
	                                &g_state.skel->links.openat_e,
	                                TTM_OPENAT);
}

int attach_openat2_toctou_mitigation_progs() {
	const int res = attach_64bit_toctou_prog(g_state.skel->progs.openat2_e,
	                                         &g_state.skel->links.openat2_e,
	                                         TTM_OPENAT2);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_openat2_e,
	                               g_state.skel->progs.ia32_openat2_e,
	                               &g_state.skel->links.ia32_compat_openat2_e,
	                               &g_state.skel->links.ia32_openat2_e);
}

/*=============================== ATTACH PROGRAMS ===============================*/

/*=============================== DETACH PROGRAMS ===============================*/

int detach_syscall_exit_dispatcher() {
	if(g_state.skel->links.sys_exit && bpf_link__destroy(g_state.skel->links.sys_exit)) {
		log_errorf("failed to detach the 'sys_exit' program");
		return errno;
	}
	g_state.skel->links.sys_exit = NULL;
	return 0;
}

int detach_sched_proc_exit() {
	if(g_state.skel->links.sched_proc_exit &&
	   bpf_link__destroy(g_state.skel->links.sched_proc_exit)) {
		log_errorf("failed to detach the 'sched_proc_exit' program");
		return errno;
	}
	g_state.skel->links.sched_proc_exit = NULL;
	return 0;
}

int detach_sched_switch() {
	if(g_state.skel->links.sched_switch && bpf_link__destroy(g_state.skel->links.sched_switch)) {
		log_errorf("failed to detach the 'sched_switch' program");
		return errno;
	}
	g_state.skel->links.sched_switch = NULL;
	return 0;
}

int detach_sched_proc_exec() {
	if(g_state.skel->links.sched_p_exec && bpf_link__destroy(g_state.skel->links.sched_p_exec)) {
		log_errorf("failed to detach the 'sched_proc_exec' program");
		return errno;
	}
	g_state.skel->links.sched_p_exec = NULL;
	return 0;
}

int detach_sched_proc_fork() {
#ifdef CAPTURE_SCHED_PROC_FORK
	if(g_state.skel->links.sched_p_fork && bpf_link__destroy(g_state.skel->links.sched_p_fork)) {
		log_errorf("failed to detach the 'sched_proc_fork' program");
		return errno;
	}
	g_state.skel->links.sched_p_fork = NULL;
#endif
	return 0;
}

int detach_page_fault_user() {
#ifdef CAPTURE_PAGE_FAULTS
	if(g_state.skel->links.pf_user && bpf_link__destroy(g_state.skel->links.pf_user)) {
		log_errorf("failed to detach the 'pf_user' program");
		return errno;
	}
	g_state.skel->links.pf_user = NULL;
#endif
	return 0;
}

int detach_page_fault_kernel() {
#ifdef CAPTURE_PAGE_FAULTS
	if(g_state.skel->links.pf_kernel && bpf_link__destroy(g_state.skel->links.pf_kernel)) {
		log_errorf("failed to detach the 'pf_kernel' program");
		return errno;
	}
	g_state.skel->links.pf_kernel = NULL;
#endif
	return 0;
}

int detach_signal_deliver() {
	if(g_state.skel->links.signal_deliver &&
	   bpf_link__destroy(g_state.skel->links.signal_deliver)) {
		log_errorf("failed to detach the 'signal_deliver' program");
		return errno;
	}
	g_state.skel->links.signal_deliver = NULL;
	return 0;
}

static void print_prog_detachment_failure_error(const struct bpf_program* prog) {
	const char* prog_name = bpf_program__name(prog);
	log_errorf("failed to detach the '%s' program", prog_name);
}

static int detach_toctou_progs(const struct bpf_program* prog,
                               const struct bpf_program* ia32_compat_prog,
                               const struct bpf_program* ia32_prog,
                               struct bpf_link** prog_link,
                               struct bpf_link** ia32_compat_prog_link,
                               struct bpf_link** ia32_prog_link,
                               enum ttm_sc_code sc) {
	if(*prog_link && bpf_link__destroy(*prog_link)) {
		print_prog_detachment_failure_error(prog);
		return errno;
	}
	*prog_link = NULL;
	close_toctou_perf_events_of(sc);

	if(*ia32_compat_prog_link && bpf_link__destroy(*ia32_compat_prog_link)) {
		print_prog_detachment_failure_error(ia32_compat_prog);
		return errno;
	}
	*ia32_compat_prog_link = NULL;

	if(*ia32_prog_link && bpf_link__destroy(*ia32_prog_link)) {
		print_prog_detachment_failure_error(ia32_prog);
		return errno;
	}
	*ia32_prog_link = NULL;

	return 0;
}

int detach_connect_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.connect_e,
	                           g_state.skel->progs.ia32_compat_connect_e,
	                           g_state.skel->progs.ia32_connect_e,
	                           &g_state.skel->links.connect_e,
	                           &g_state.skel->links.ia32_compat_connect_e,
	                           &g_state.skel->links.ia32_connect_e,
	                           TTM_CONNECT);
}

int detach_creat_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.creat_e,
	                           g_state.skel->progs.ia32_compat_creat_e,
	                           g_state.skel->progs.ia32_creat_e,
	                           &g_state.skel->links.creat_e,
	                           &g_state.skel->links.ia32_compat_creat_e,
	                           &g_state.skel->links.ia32_creat_e,
	                           TTM_CREAT);
}

int detach_open_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.open_e,
	                           g_state.skel->progs.ia32_compat_open_e,
	                           g_state.skel->progs.ia32_open_e,
	                           &g_state.skel->links.open_e,
	                           &g_state.skel->links.ia32_compat_open_e,
	                           &g_state.skel->links.ia32_open_e,
	                           TTM_OPEN);
}

int detach_openat_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.openat_e,
	                           g_state.skel->progs.ia32_compat_openat_e,
	                           g_state.skel->progs.ia32_openat_e,
	                           &g_state.skel->links.openat_e,
	                           &g_state.skel->links.ia32_compat_openat_e,
	                           &g_state.skel->links.ia32_openat_e,
	                           TTM_OPENAT);
}

int detach_openat2_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.openat2_e,
	                           g_state.skel->progs.ia32_compat_openat2_e,
	                           g_state.skel->progs.ia32_openat2_e,
	                           &g_state.skel->links.openat2_e,
	                           &g_state.skel->links.ia32_compat_openat2_e,
	                           &g_state.skel->links.ia32_openat2_e,
	                           TTM_OPENAT2);
}

/*=============================== DETACH PROGRAMS ===============================*/
