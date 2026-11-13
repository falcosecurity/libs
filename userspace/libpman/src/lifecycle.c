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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "state.h"
#include <driver/feature_gates.h>
#include "events_prog_table.h"
#include "support_probing.h"
#include "programs.h"
#include <fcntl.h>
#include <linux/random.h>
#include <sched.h>
#include <sys/syscall.h>
#include <time.h>

int pman_open_probe() {
	g_state.skel = bpf_probe__open();
	if(!g_state.skel) {
		log_errorf("failed to open BPF skeleton");
		return errno;
	}
	return 0;
}

static void disable_prog_autoloading(const char *prog_name) {
	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "disabling BPF program '%s'", prog_name);
	struct bpf_program *p = bpf_object__find_program_by_name(g_state.skel->obj, prog_name);
	if(!p || bpf_program__set_autoload(p, false) < 0) {
		log_errorf("failed to disable prog '%s'", prog_name);
		return;
	}
	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "disabled BPF program '%s'", prog_name);
}

// note: this temporarily disables logging.
static bool is_kernel_symbol_available(const char *symbol) {
	// note: `libbpf_find_vmlinux_btf_id()` emits a log line at warning level if the symbol is not
	// available. Temporarily disable it to avoid polluting the log stream.
	const libbpf_print_fn_t old_log_handler = libbpf_set_print(NULL);
	// Actually, 0 corresponds to `BPF_CGROUP_INET_INGRESS`, but use it as "no attach type" value as
	// currently, the kernel reacts by searching for the availability of the requested symbol
	// without adding any prefix to it (that is what we want).
	const int NO_ATTACH_TYPE = 0;
	const bool is_available = libbpf_find_vmlinux_btf_id(symbol, NO_ATTACH_TYPE) >= 0;
	libbpf_set_print(old_log_handler);
	return is_available;
}

#ifdef BPF_ITERATOR_SUPPORT
static void prepare_iter_progs_before_loading() {
	// Disable autoloading for all iterator programs if iterators support is disabled.
	if(g_state.iterators_disabled) {
		for(int i = 0; i < ITER_PROG_MAX; i++) {
			const iter_prog_t *iter_prog = &iter_progs_table[i];
			const char *prog_name = iter_prog->name;
			log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
			         "disabled BPF program '%s' (due to disabled BPF iterators support)",
			         prog_name);
			disable_prog_autoloading(prog_name);
			*iter_prog->feature_flag = false;
		}
		return;
	}

	// Disable autoloading for unsupported iterator programs.
	for(int i = 0; i < ITER_PROG_MAX; i++) {
		const iter_prog_t *iter_prog = &iter_progs_table[i];
		const char *prog_name = iter_prog->name;
		const bool is_prog_supported = iter_support_probing__probe(prog_name) == 0;
		if(!is_prog_supported) {
			log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "unsupported BPF program '%s'", prog_name);
			disable_prog_autoloading(prog_name);
		} else {
			log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "supported BPF program '%s'", prog_name);
		}

		// Update the corresponding feature flag in `g_state`.
		*iter_prog->feature_flag = is_prog_supported;
	}
}
#endif

/* Whether this kernel provides everything a program declares it needs. */
static bool prog_requirements_met(const event_prog_t *prog) {
	if(prog->feat > 0 &&
	   libbpf_probe_bpf_helper(BPF_PROG_TYPE_RAW_TRACEPOINT, prog->feat, NULL) != 1) {
		return false;
	}
	if(prog->needs_bpf_atomics && !g_state.skel->rodata->g_bpf_atomics) {
		log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		         "BPF program '%s' needs the BPF atomics, which this kernel does not have",
		         prog->name);
		return false;
	}
	return true;
}

int pman_prepare_progs_before_loading() {
	/*
	 * Probe required features for each bpf program, as requested
	 */
	errno = 0;
	for(int ev = 0; ev < PPM_EVENT_MAX; ev++) {
		// We dropped the support for programs generating enter events, except for the ones managing
		// TOCTOU mitigation (handled separately below).
		if(PPME_IS_ENTER(ev)) {
			continue;
		}
		event_prog_t *progs = exit_event_progs_table[ev];
		int idx, chosen_idx = -1;
		for(idx = 0; idx < MAX_FEATURE_CHECKS && progs[idx].name != NULL; idx++) {
			bool should_disable = chosen_idx != -1;
			if(!should_disable) {
				if(!prog_requirements_met(&progs[idx])) {
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "BPF program '%s' did not satisfy required feature [%d]",
					         progs[idx].name,
					         progs[idx].feat);
					// Required feature not present
					should_disable = true;
				} else {
					// We satisfied requested feature
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "BPF program '%s' satisfied required feature [%d]",
					         progs[idx].name,
					         progs[idx].feat);
					chosen_idx = idx;
				}
			}

			// Disable autoloading for all programs except chosen one
			if(should_disable) {
				disable_prog_autoloading(progs[idx].name);
			}
		}

		// In case we couldn't find any program satisfying required features, give an error.
		// As of today, this will never happen, but better safe than sorry.
		if(chosen_idx == -1 && progs[0].name != NULL) {
			log_errorf("no program satisfies required features for event %d", ev);
			errno = ENXIO;
			return errno;
		}

		event_prog_t old_prog = progs[0];
		// Always move the selected program to index 0 to be easily accessed by maps.c
		// If no programs are skipped, the following line expands to progs[0] = progs[0];
		progs[0] = progs[chosen_idx];

		// To be able to reload the probe, we need to still reference the old
		// program to set its autoload to false.
		// Ie: in case of:
		// * open()
		// * close()
		// * open()
		progs[chosen_idx] = old_prog;
	}

	// Keep autoloading enabled for all TOCTOU mitigation 64 bit programs.
	// Disable autoloading for unsupported TOCTOU mitigation ia-32 programs.
	for(int i = 0; i < TTM_MAX; i++) {
		const ttm_ia32_prog_t *ia32_progs = ttm_progs_table[i].ttm_ia32_progs;
		int chosen_idx = -1;
		for(int j = 0; j < TTM_IA32_PROGS_NUM; j++) {
			const ttm_ia32_prog_t *ia32_prog = &ia32_progs[j];
			bool should_disable = chosen_idx != -1;
			if(!should_disable) {
				if(!is_kernel_symbol_available(ia32_prog->kernel_symbol)) {
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "kernel symbol '%s' (required by BPF program '%s') not available",
					         ia32_prog->kernel_symbol,
					         ia32_prog->name);
					should_disable = true;
				} else {
					// We satisfied requested feature
					log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
					         "kernel symbol '%s' (required by BPF program '%s') is available",
					         ia32_prog->kernel_symbol,
					         ia32_prog->name);
					chosen_idx = j;
				}
			}
			// Disable autoloading for all programs except chosen one.
			if(should_disable) {
				disable_prog_autoloading(ia32_prog->name);
			}
		}
	}

#ifdef BPF_ITERATOR_SUPPORT
	prepare_iter_progs_before_loading();
#endif

	return 0;
}

static int bpf_prog_fd_or_default(const struct bpf_program *prog) {
	const int fd = bpf_program__fd(prog);
	if(fd < 0) {
		return -1;
	}
	return fd;
}

static void save_attached_progs() {
	g_state.attached_progs_fds[0] = bpf_prog_fd_or_default(g_state.skel->progs.sys_exit);
	g_state.attached_progs_fds[1] = bpf_prog_fd_or_default(g_state.skel->progs.sched_proc_exit);
	g_state.attached_progs_fds[2] = bpf_prog_fd_or_default(g_state.skel->progs.sched_switch);
	g_state.attached_progs_fds[3] = bpf_prog_fd_or_default(g_state.skel->progs.sched_p_exec);
#ifdef CAPTURE_SCHED_PROC_FORK
	g_state.attached_progs_fds[4] = bpf_prog_fd_or_default(g_state.skel->progs.sched_p_fork);
#endif
#ifdef CAPTURE_PAGE_FAULTS
	g_state.attached_progs_fds[5] = bpf_prog_fd_or_default(g_state.skel->progs.pf_user);
	g_state.attached_progs_fds[6] = bpf_prog_fd_or_default(g_state.skel->progs.pf_kernel);
#endif
	g_state.attached_progs_fds[7] = bpf_prog_fd_or_default(g_state.skel->progs.signal_deliver);
	g_state.attached_progs_fds[8] = bpf_prog_fd_or_default(g_state.skel->progs.connect_e);
	g_state.attached_progs_fds[9] =
	        bpf_prog_fd_or_default(g_state.skel->progs.ia32_compat_connect_e);
	g_state.attached_progs_fds[10] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_connect_e);
	g_state.attached_progs_fds[11] = bpf_prog_fd_or_default(g_state.skel->progs.creat_e);
	g_state.attached_progs_fds[12] =
	        bpf_prog_fd_or_default(g_state.skel->progs.ia32_compat_creat_e);
	g_state.attached_progs_fds[13] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_creat_e);
	g_state.attached_progs_fds[14] = bpf_prog_fd_or_default(g_state.skel->progs.open_e);
	g_state.attached_progs_fds[15] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_compat_open_e);
	g_state.attached_progs_fds[16] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_open_e);
	g_state.attached_progs_fds[17] = bpf_prog_fd_or_default(g_state.skel->progs.openat_e);
	g_state.attached_progs_fds[18] =
	        bpf_prog_fd_or_default(g_state.skel->progs.ia32_compat_openat_e);
	g_state.attached_progs_fds[19] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_openat_e);
	g_state.attached_progs_fds[20] = bpf_prog_fd_or_default(g_state.skel->progs.openat2_e);
	g_state.attached_progs_fds[21] =
	        bpf_prog_fd_or_default(g_state.skel->progs.ia32_compat_openat2_e);
	g_state.attached_progs_fds[22] = bpf_prog_fd_or_default(g_state.skel->progs.ia32_openat2_e);
#ifdef BPF_ITERATOR_SUPPORT
	g_state.attached_progs_fds[23] = bpf_prog_fd_or_default(g_state.skel->progs.dump_task);
	g_state.attached_progs_fds[24] = bpf_prog_fd_or_default(g_state.skel->progs.dump_task_file);
#endif
}

// Pick the mode of the `faccessat` calls that `syscall_tp_check` counts. Each check picks a random
// mode, so two libpman instances that make the check at the same time do not count the calls of
// each other. The mode has bits outside `S_IRWXO`, so the kernel rejects the calls with EINVAL
// right after the tracepoint.
static uint32_t syscall_tp_check_mode() {
	uint32_t nonce = 0;
	if(syscall(__NR_getrandom, &nonce, sizeof(nonce), GRND_NONBLOCK) != (long)sizeof(nonce)) {
		struct timespec ts = {0};
		clock_gettime(CLOCK_MONOTONIC, &ts);
		nonce = (uint32_t)ts.tv_nsec ^ ((uint32_t)syscall(__NR_gettid) << 16);
	}
	return nonce | 0x40000000;
}

// Tell whether BPF programs on syscall tracepoints that read user memory miss some CPUs. Some
// kernels run them only on the CPUs where a perf event of the tracepoint is active. They carry
// commit 2c2b322acdcc ("tracing: perf: Fix stale head for perf syscall tracing") without commit
// 57918341dd19. libbpf attaches a program through one perf event on CPU 0, so on these kernels
// the program runs only for system calls on CPU 0.
//
// The check attaches `syscall_tp_check` to `syscalls/sys_enter_faccessat` and makes one `faccessat`
// call on each CPU that this thread can use. It runs before any other program is attached, so no
// event reaches the ring buffers.
static bool syscall_tracepoints_miss_cpus() {
	if(g_state.n_possible_cpus <= 1) {
		return false;
	}

	struct bpf_link *link = bpf_program__attach(g_state.skel->progs.syscall_tp_check);
	if(!link) {
		log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		         "cannot attach the 'syscall_tp_check' program: assume that BPF programs on "
		         "syscall tracepoints run on every CPU");
		return false;
	}

	const size_t set_size = CPU_ALLOC_SIZE(g_state.n_possible_cpus);
	cpu_set_t *allowed = CPU_ALLOC(g_state.n_possible_cpus);
	cpu_set_t *one = CPU_ALLOC(g_state.n_possible_cpus);
	uint64_t calls = 0;
	bool affinity_known = false;
	if(allowed && one && sched_getaffinity(0, set_size, allowed) == 0) {
		affinity_known = true;
		const uint32_t mode = syscall_tp_check_mode();
		g_state.skel->bss->syscall_tp_check__mode = mode;
		g_state.skel->bss->syscall_tp_check__hits = 0;
		for(int cpu = 0; cpu < g_state.n_possible_cpus; cpu++) {
			if(!CPU_ISSET_S(cpu, set_size, allowed)) {
				continue;
			}
			CPU_ZERO_S(set_size, one);
			CPU_SET_S(cpu, set_size, one);
			// The thread runs on `cpu` when the call returns.
			if(sched_setaffinity(0, set_size, one) != 0) {
				continue;
			}
			syscall(__NR_faccessat, AT_FDCWD, "", (long)mode);
			calls++;
		}
		if(sched_setaffinity(0, set_size, allowed) != 0) {
			log_msgf(FALCOSECURITY_LOG_SEV_WARNING,
			         "cannot restore the CPU affinity of the thread after the syscall tracepoint "
			         "check");
		}
	}
	const uint64_t hits = *(volatile uint64_t *)&g_state.skel->bss->syscall_tp_check__hits;
	CPU_FREE(allowed);
	CPU_FREE(one);

	if(bpf_link__destroy(link)) {
		log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "cannot detach the 'syscall_tp_check' program");
	}

	// The `faccessat` calls fail with EINVAL on purpose: do not report that in the messages below.
	errno = 0;

	// With fewer than two CPUs, the check cannot tell whether the only CPU is the one with the
	// perf event of libbpf.
	if(!affinity_known || calls < 2) {
		log_msgf(FALCOSECURITY_LOG_SEV_INFO,
		         "cannot check whether BPF programs on syscall tracepoints run on every CPU: "
		         "assume that they do not");
		return true;
	}
	if(hits < calls) {
		log_msgf(FALCOSECURITY_LOG_SEV_WARNING,
		         "BPF programs on syscall tracepoints that read user memory ran on %llu of %llu "
		         "CPUs: open perf events to make the TOCTOU mitigation programs run on every CPU",
		         (unsigned long long)hits,
		         (unsigned long long)calls);
		return true;
	}
	return false;
}

int pman_load_probe() {
	if(bpf_probe__load(g_state.skel)) {
		log_errorf("failed to load BPF object");
		return errno;
	}
	save_attached_progs();
	g_state.ttm_needs_perf_events = syscall_tracepoints_miss_cpus();
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

	if(g_state.inner_ringbuf_map_fd != -1) {
		close(g_state.inner_ringbuf_map_fd);
		g_state.inner_ringbuf_map_fd = -1;
	}

	for(int i = 0; i < MODERN_BPF_PROG_ATTACHED_MAX; i++) {
		g_state.attached_progs_fds[i] = -1;
	}

	if(g_state.cons_pos) {
		free(g_state.cons_pos);
		g_state.cons_pos = NULL;
	}

	if(g_state.prod_pos) {
		free(g_state.prod_pos);
		g_state.prod_pos = NULL;
	}

	close_toctou_perf_events();

	if(g_state.skel) {
		bpf_probe__detach(g_state.skel);
		bpf_probe__destroy(g_state.skel);
		g_state.skel = NULL;
	}

	if(g_state.rb_manager) {
		ring_buffer__free(g_state.rb_manager);
		g_state.rb_manager = NULL;
	}

#ifdef BPF_ITERATOR_SUPPORT

	/* BPF iterators section */
	g_state.is_tasks_dumping_supported = false;
	g_state.is_task_files_dumping_supported = false;
	memset(&g_state.bpf_iter_link_info_supp_info, 0, sizeof(g_state.bpf_iter_link_info_supp_info));

#endif /* BPF_ITERATOR_SUPPORT */
}
