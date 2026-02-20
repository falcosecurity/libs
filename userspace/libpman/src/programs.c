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
#include <libpman.h>

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

/*=============================== ATTACH PROGRAMS ===============================*/

int pman_attach_syscall_exit_dispatcher() {
	/* The program is already attached. */
	if(g_state.skel->links.sys_exit != NULL) {
		return 0;
	}

	g_state.skel->links.sys_exit = bpf_program__attach(g_state.skel->progs.sys_exit);
	if(!g_state.skel->links.sys_exit) {
		pman_print_errorf("failed to attach the 'sys_exit' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_exit() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_proc_exit != NULL) {
		return 0;
	}

	g_state.skel->links.sched_proc_exit = bpf_program__attach(g_state.skel->progs.sched_proc_exit);
	if(!g_state.skel->links.sched_proc_exit) {
		pman_print_errorf("failed to attach the 'sched_proc_exit' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_switch() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_switch != NULL) {
		return 0;
	}

	g_state.skel->links.sched_switch = bpf_program__attach(g_state.skel->progs.sched_switch);
	if(!g_state.skel->links.sched_switch) {
		pman_print_errorf("failed to attach the 'sched_switch' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_exec() {
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_exec != NULL) {
		return 0;
	}

	g_state.skel->links.sched_p_exec = bpf_program__attach(g_state.skel->progs.sched_p_exec);
	if(!g_state.skel->links.sched_p_exec) {
		pman_print_errorf("failed to attach the 'sched_proc_exec' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_fork() {
#ifdef CAPTURE_SCHED_PROC_FORK
	/* The program is already attached. */
	if(g_state.skel->links.sched_p_fork != NULL) {
		return 0;
	}

	g_state.skel->links.sched_p_fork = bpf_program__attach(g_state.skel->progs.sched_p_fork);
	if(!g_state.skel->links.sched_p_fork) {
		pman_print_errorf("failed to attach the 'sched_proc_fork' program");
		return errno;
	}
#endif
	return 0;
}

int pman_attach_page_fault_user() {
#ifdef CAPTURE_PAGE_FAULTS
	/* The program is already attached. */
	if(g_state.skel->links.pf_user != NULL) {
		return 0;
	}

	g_state.skel->links.pf_user = bpf_program__attach(g_state.skel->progs.pf_user);
	if(!g_state.skel->links.pf_user) {
		pman_print_errorf("failed to attach the 'pf_user' program");
		return errno;
	}
#endif
	return 0;
}

int pman_attach_page_fault_kernel() {
#ifdef CAPTURE_PAGE_FAULTS
	/* The program is already attached. */
	if(g_state.skel->links.pf_kernel != NULL) {
		return 0;
	}

	g_state.skel->links.pf_kernel = bpf_program__attach(g_state.skel->progs.pf_kernel);
	if(!g_state.skel->links.pf_kernel) {
		pman_print_errorf("failed to attach the 'pf_kernel' program");
		return errno;
	}
#endif
	return 0;
}

int pman_attach_signal_deliver() {
	/* The program is already attached. */
	if(g_state.skel->links.signal_deliver != NULL) {
		return 0;
	}

	g_state.skel->links.signal_deliver = bpf_program__attach(g_state.skel->progs.signal_deliver);
	if(!g_state.skel->links.signal_deliver) {
		pman_print_errorf("failed to attach the 'signal_deliver' program");
		return errno;
	}
	return 0;
}

static int attach_64bit_toctou_prog(const struct bpf_program* prog, struct bpf_link** prog_link) {
	if(*prog_link != NULL) {
		return 0;
	}
	*prog_link = bpf_program__attach(prog);
	if(!*prog_link) {
		return errno;
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

int pman_attach_connect_toctou_mitigation_progs() {
	const int res =
	        attach_64bit_toctou_prog(g_state.skel->progs.connect_e, &g_state.skel->links.connect_e);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_connect_e,
	                               g_state.skel->progs.ia32_connect_e,
	                               &g_state.skel->links.ia32_compat_connect_e,
	                               &g_state.skel->links.ia32_connect_e);
}

int pman_attach_creat_toctou_mitigation_progs() {
	const int res =
	        attach_64bit_toctou_prog(g_state.skel->progs.creat_e, &g_state.skel->links.creat_e);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_creat_e,
	                               g_state.skel->progs.ia32_creat_e,
	                               &g_state.skel->links.ia32_compat_creat_e,
	                               &g_state.skel->links.ia32_creat_e);
}

int pman_attach_open_toctou_mitigation_progs() {
	const int res =
	        attach_64bit_toctou_prog(g_state.skel->progs.open_e, &g_state.skel->links.open_e);
	if(res) {
		return res;
	}
	return attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_open_e,
	                               g_state.skel->progs.ia32_open_e,
	                               &g_state.skel->links.ia32_compat_open_e,
	                               &g_state.skel->links.ia32_open_e);
}

int pman_attach_openat_toctou_mitigation_progs() {
	// Attach ia-32 programs before 64 bit program, otherwise the 64 bit program will generate
	// events for the ia-32 programs attachment attempts.
	const int res = attach_ia32_toctou_prog(g_state.skel->progs.ia32_compat_openat_e,
	                                        g_state.skel->progs.ia32_openat_e,
	                                        &g_state.skel->links.ia32_compat_openat_e,
	                                        &g_state.skel->links.ia32_openat_e);
	if(res) {
		return res;
	}
	return attach_64bit_toctou_prog(g_state.skel->progs.openat_e, &g_state.skel->links.openat_e);
}

int pman_attach_openat2_toctou_mitigation_progs() {
	const int res =
	        attach_64bit_toctou_prog(g_state.skel->progs.openat2_e, &g_state.skel->links.openat2_e);
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

int pman_detach_syscall_exit_dispatcher() {
	if(g_state.skel->links.sys_exit && bpf_link__destroy(g_state.skel->links.sys_exit)) {
		pman_print_errorf("failed to detach the 'sys_exit' program");
		return errno;
	}
	g_state.skel->links.sys_exit = NULL;
	return 0;
}

int pman_detach_sched_proc_exit() {
	if(g_state.skel->links.sched_proc_exit &&
	   bpf_link__destroy(g_state.skel->links.sched_proc_exit)) {
		pman_print_errorf("failed to detach the 'sched_proc_exit' program");
		return errno;
	}
	g_state.skel->links.sched_proc_exit = NULL;
	return 0;
}

int pman_detach_sched_switch() {
	if(g_state.skel->links.sched_switch && bpf_link__destroy(g_state.skel->links.sched_switch)) {
		pman_print_errorf("failed to detach the 'sched_switch' program");
		return errno;
	}
	g_state.skel->links.sched_switch = NULL;
	return 0;
}

int pman_detach_sched_proc_exec() {
	if(g_state.skel->links.sched_p_exec && bpf_link__destroy(g_state.skel->links.sched_p_exec)) {
		pman_print_errorf("failed to detach the 'sched_proc_exec' program");
		return errno;
	}
	g_state.skel->links.sched_p_exec = NULL;
	return 0;
}

int pman_detach_sched_proc_fork() {
#ifdef CAPTURE_SCHED_PROC_FORK
	if(g_state.skel->links.sched_p_fork && bpf_link__destroy(g_state.skel->links.sched_p_fork)) {
		pman_print_errorf("failed to detach the 'sched_proc_fork' program");
		return errno;
	}
	g_state.skel->links.sched_p_fork = NULL;
#endif
	return 0;
}

int pman_detach_page_fault_user() {
#ifdef CAPTURE_PAGE_FAULTS
	if(g_state.skel->links.pf_user && bpf_link__destroy(g_state.skel->links.pf_user)) {
		pman_print_errorf("failed to detach the 'pf_user' program");
		return errno;
	}
	g_state.skel->links.pf_user = NULL;
#endif
	return 0;
}

int pman_detach_page_fault_kernel() {
#ifdef CAPTURE_PAGE_FAULTS
	if(g_state.skel->links.pf_kernel && bpf_link__destroy(g_state.skel->links.pf_kernel)) {
		pman_print_errorf("failed to detach the 'pf_kernel' program");
		return errno;
	}
	g_state.skel->links.pf_kernel = NULL;
#endif
	return 0;
}

int pman_detach_signal_deliver() {
	if(g_state.skel->links.signal_deliver &&
	   bpf_link__destroy(g_state.skel->links.signal_deliver)) {
		pman_print_errorf("failed to detach the 'signal_deliver' program");
		return errno;
	}
	g_state.skel->links.signal_deliver = NULL;
	return 0;
}

static void print_prog_detachment_failure_error(const struct bpf_program* prog) {
	const char* prog_name = bpf_program__name(prog);
	pman_print_errorf("failed to detach the '%s' program", prog_name);
}

static int detach_toctou_progs(const struct bpf_program* prog,
                               const struct bpf_program* ia32_compat_prog,
                               const struct bpf_program* ia32_prog,
                               struct bpf_link** prog_link,
                               struct bpf_link** ia32_compat_prog_link,
                               struct bpf_link** ia32_prog_link) {
	if(*prog_link && bpf_link__destroy(*prog_link)) {
		print_prog_detachment_failure_error(prog);
		return errno;
	}
	*prog_link = NULL;

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

int pman_detach_connect_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.connect_e,
	                           g_state.skel->progs.ia32_compat_connect_e,
	                           g_state.skel->progs.ia32_connect_e,
	                           &g_state.skel->links.connect_e,
	                           &g_state.skel->links.ia32_compat_connect_e,
	                           &g_state.skel->links.ia32_connect_e);
}

int pman_detach_creat_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.creat_e,
	                           g_state.skel->progs.ia32_compat_creat_e,
	                           g_state.skel->progs.ia32_creat_e,
	                           &g_state.skel->links.creat_e,
	                           &g_state.skel->links.ia32_compat_creat_e,
	                           &g_state.skel->links.ia32_creat_e);
}

int pman_detach_open_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.open_e,
	                           g_state.skel->progs.ia32_compat_open_e,
	                           g_state.skel->progs.ia32_open_e,
	                           &g_state.skel->links.open_e,
	                           &g_state.skel->links.ia32_compat_open_e,
	                           &g_state.skel->links.ia32_open_e);
}

int pman_detach_openat_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.openat_e,
	                           g_state.skel->progs.ia32_compat_openat_e,
	                           g_state.skel->progs.ia32_openat_e,
	                           &g_state.skel->links.openat_e,
	                           &g_state.skel->links.ia32_compat_openat_e,
	                           &g_state.skel->links.ia32_openat_e);
}

int pman_detach_openat2_toctou_mitigation_progs() {
	return detach_toctou_progs(g_state.skel->progs.openat2_e,
	                           g_state.skel->progs.ia32_compat_openat2_e,
	                           g_state.skel->progs.ia32_openat2_e,
	                           &g_state.skel->links.openat2_e,
	                           &g_state.skel->links.ia32_compat_openat2_e,
	                           &g_state.skel->links.ia32_openat2_e);
}

/*=============================== DETACH PROGRAMS ===============================*/
