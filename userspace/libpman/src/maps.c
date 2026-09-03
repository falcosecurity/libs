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

#include <stdint.h>
#include "events_prog_table.h"
#include "support_probing.h"
#include <libscap/scap.h>
#include <bpf/bpf.h>
#include <string.h>

/* Some exit events can require more than one bpf program to collect all the data. */
static const char* sys_exit_extra_event_names[SYS_EXIT_EXTRA_CODE_MAX] = {
        [T1_EXECVE_X] = "t1_execve_x",
        [T1_EXECVEAT_X] = "t1_execveat_x",
        [T1_CLONE_X] = "t1_clone_x",
        [T1_CLONE3_X] = "t1_clone3_x",
        [T1_FORK_X] = "t1_fork_x",
        [T1_VFORK_X] = "t1_vfork_x",
        [T2_CLONE_X] = "t2_clone_x",
        [T2_CLONE3_X] = "t2_clone3_x",
        [T2_FORK_X] = "t2_fork_x",
        [T2_VFORK_X] = "t2_vfork_x",
        [T1_OPEN_BY_HANDLE_AT_X] = "t1_open_by_handle_at_x",
        [T2_EXECVE_X] = "t2_execve_x",
        [T2_EXECVEAT_X] = "t2_execveat_x",
        [T3_EXECVE_X] = "t3_execve_x",
        [T3_EXECVEAT_X] = "t3_execveat_x",
};

extern const struct ppm_event_info g_event_info[PPM_EVENT_MAX];
extern const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];
extern const int g_ia32_64_map[];

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/// TODO: in a future optimization we can think to remove this table,
/// defining macros for `nparams` and directly use them inside bpf
/// programs instead of reading from a map.
static void fill_event_params_table() {
	uint8_t nparams_event = 0;

	for(int j = 0; j < PPM_EVENT_MAX; ++j) {
		nparams_event = (uint8_t)g_event_info[j].nparams;
		g_state.skel->rodata->g_event_params_table[j] = nparams_event;
	}
}

static void fill_ppm_sc_table() {
	for(int j = 0; j < SYSCALL_TABLE_SIZE; ++j) {
		g_state.skel->rodata->g_ppm_sc_table[j] = (uint16_t)g_syscall_table[j].ppm_sc;
	}
}

uint64_t pman_get_probe_api_ver() {
	return g_state.skel->rodata->probe_api_ver;
}

uint64_t pman_get_probe_schema_ver() {
	return g_state.skel->rodata->probe_schema_var;
}

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/*=============================== BPF GLOBAL VARIABLES ===============================*/

static int get_capture_settings(struct capture_settings* settings) {
	int last_errno;

	const int fd = bpf_map__fd(g_state.skel->maps.capture_settings);
	if(fd < 0) {
		last_errno = errno;
		log_errorf("unable to get capture_settings map fd!");
		return last_errno;
	}

	const uint32_t key = 0;
	if(bpf_map_lookup_elem(fd, &key, settings)) {
		last_errno = errno;
		log_errorf("unable to get capture_settings!");
		return last_errno;
	}

	return 0;
}

static int update_capture_settings(struct capture_settings* settings) {
	int last_errno;

	const int fd = bpf_map__fd(g_state.skel->maps.capture_settings);
	if(fd < 0) {
		last_errno = errno;
		log_errorf("unable to get capture_settings map fd!");
		return last_errno;
	}

	const uint32_t key = 0;
	if(bpf_map_update_elem(fd, &key, settings, BPF_ANY)) {
		last_errno = errno;
		log_errorf("unable to initialize capture_settings map!");
		return last_errno;
	}

	return 0;
}

void pman_set_snaplen(uint32_t desired_snaplen) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.snaplen = desired_snaplen;
	update_capture_settings(&settings);
}

void pman_set_boot_time(uint64_t boot_time) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.boot_time = boot_time;
	update_capture_settings(&settings);
}

void pman_set_dropping_mode(bool value) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.dropping_mode = value;
	update_capture_settings(&settings);
}

void pman_set_sampling_ratio(uint32_t value) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.sampling_ratio = value;
	update_capture_settings(&settings);
}

void pman_set_drop_failed(bool drop_failed) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.drop_failed = drop_failed;
	update_capture_settings(&settings);
}

void pman_set_do_dynamic_snaplen(bool do_dynamic_snaplen) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.do_dynamic_snaplen = do_dynamic_snaplen;
	update_capture_settings(&settings);
}

void pman_set_fullcapture_port_range(uint16_t range_start, uint16_t range_end) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.fullcapture_port_range_start = range_start;
	settings.fullcapture_port_range_end = range_end;
	update_capture_settings(&settings);
}

void pman_set_statsd_port(uint16_t statsd_port) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.statsd_port = statsd_port;
	update_capture_settings(&settings);
}

void pman_set_scap_tid(int32_t scap_tid) {
	struct capture_settings settings;
	if(get_capture_settings(&settings) != 0) {
		return;
	}
	settings.scap_tid = scap_tid;
	update_capture_settings(&settings);
}

static void fill_syscall_sampling_table() {
	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++) {
		if(g_syscall_table[syscall_id].flags & UF_NEVER_DROP) {
			g_state.skel->rodata->g_64bit_sampling_syscall_table[syscall_id] = UF_NEVER_DROP;
			continue;
		}

		/* Syscalls with `g_syscall_table[syscall_id].flags == UF_NONE` are the generic ones */
		if(g_syscall_table[syscall_id].flags & UF_ALWAYS_DROP ||
		   g_syscall_table[syscall_id].flags == UF_NONE) {
			g_state.skel->rodata->g_64bit_sampling_syscall_table[syscall_id] = UF_ALWAYS_DROP;
			continue;
		}

		if(g_syscall_table[syscall_id].flags & UF_USED) {
			g_state.skel->rodata->g_64bit_sampling_syscall_table[syscall_id] = 0;
			continue;
		}
	}
}

static void fill_ia32_to_64_table() {
	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++) {
		// Note: we will map all syscalls from the upper limit of the ia32 table
		// up to SYSCALL_TABLE_SIZE to 0 (because they are not set in the g_ia32_64_map).
		// 0 is read on x86_64; this is not a problem though because
		// we will never receive a 32bit syscall above the upper limit, since it won't be existent.
		const int x64_val = g_ia32_64_map[syscall_id];
		g_state.skel->rodata->g_ia32_to_64_table[syscall_id] = x64_val;
	}
}

/*=============================== BPF GLOBAL VARIABLES ===============================*/

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

static int add_bpf_program_to_tail_table(int tail_table_fd, const char* bpf_prog_name, int key) {
	struct bpf_program* bpf_prog =
	        bpf_object__find_program_by_name(g_state.skel->obj, bpf_prog_name);
	if(!bpf_prog) {
		log_msgf(FALCOSECURITY_LOG_SEV_DEBUG, "unable to find BPF program '%s'", bpf_prog_name);

		/*
		 * It's not a hard failure, as programs could be excluded from the
		 * build. There is no need to close the file descriptor yet, so return
		 * success.
		 */
		return 0;
	}

	int last_errno;
	const int bpf_prog_fd = bpf_program__fd(bpf_prog);
	if(bpf_prog_fd < 0) {
		last_errno = errno;
		log_errorf("unable to get the fd for BPF program '%s'", bpf_prog_name);
		return last_errno;
	}

	if(bpf_map_update_elem(tail_table_fd, &key, &bpf_prog_fd, BPF_ANY)) {
		last_errno = errno;
		log_errorf("unable to update the tail table with BPF program '%s'", bpf_prog_name);
		return last_errno;
	}

	return 0;
}

/**
 * @brief The syscall exit dispatcher will look into this table to understand which programs it has
 * to call:
 *
 * -> SYSCALL EXIT TAIL TABLE
 * syscall_exit_tail_table(syscall_id, exit_program_fd).
 * Returns the fd of the right bpf program to call.
 *
 * @return `0` on success, `errno` in case of error.
 */
static int fill_syscalls_tail_table() {
	const int syscall_exit_tail_table_fd = bpf_map__fd(g_state.skel->maps.syscall_exit_tail_table);
	if(syscall_exit_tail_table_fd < 0) {
		const int last_errno = errno;
		log_errorf("unable to get the syscall exit tail table");
		return last_errno;
	}

	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++) {
		/* Get event type from `g_syscall_table` */
		int exit_event_type = g_syscall_table[syscall_id].exit_event_type;

		/* If the syscall is generic, the exit event type would be `0`, but we want to associate the
		 * syscall to the `generic_x` program, so we patch it on the fly.
		 */
		if(exit_event_type == 0) {
			exit_event_type = PPME_GENERIC_X;
		}

		/* At the end of the work, we should always have a corresponding bpf tail-called program for
		 * every exit event. Until we miss some syscalls, this is not true so we manage these cases
		 * as generic events. We need to remove this workaround when all syscalls will be
		 * implemented.
		 */
		const event_prog_t* exit_prog =
		        (const event_prog_t*)&exit_event_progs_table[exit_event_type];
		if(exit_prog->name == NULL) {
			exit_prog = (const event_prog_t*)&exit_event_progs_table[PPME_GENERIC_X];
		}

		if(add_bpf_program_to_tail_table(syscall_exit_tail_table_fd, exit_prog->name, syscall_id)) {
			return errno;
		}
	}
	return 0;
}

/**
 * @brief Some sys exit bpf programs exceed the maximum complexity so they have to tail-call other
 * programs. To do that, they need a particular tail table that we call
 * `syscall_exit_extra_tail_table`.
 *
 * syscall_exit_extra_tail_table(sys_exit_extra_code, program_fd).
 *
 * `sys_exit_extra_code` is an enum defined in `/driver/ppm_events_public.h`
 *
 * @return `0` on success, `errno` in case of error.
 */
static int fill_syscall_exit_extra_tail_table() {
	const int extra_sys_exit_tail_table_fd =
	        bpf_map__fd(g_state.skel->maps.syscall_exit_extra_tail_table);
	if(extra_sys_exit_tail_table_fd < 0) {
		const int last_errno = errno;
		log_errorf("unable to get the extra sys exit tail table");
		return last_errno;
	}

	const char* tail_prog_name = NULL;
	for(int j = 0; j < SYS_EXIT_EXTRA_CODE_MAX; j++) {
		tail_prog_name = sys_exit_extra_event_names[j];
		if(!tail_prog_name) {
			log_errorf("unknown entry in the extra sys exit tail table");
			return EINVAL;
		}

		if(add_bpf_program_to_tail_table(extra_sys_exit_tail_table_fd, tail_prog_name, j)) {
			return errno;
		}
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

static int fill_interesting_syscalls_table_64bit() {
	const int fd = bpf_map__fd(g_state.skel->maps.interesting_syscalls_table_64bit);
	for(uint32_t i = 0; i < SYSCALL_TABLE_SIZE; i++) {
		const bool interesting = false;
		if(bpf_map_update_elem(fd, &i, &interesting, BPF_ANY) < 0) {
			const int last_errno = errno;
			log_errorf("unable to initialize interesting syscall table at index %d!", i);
			return last_errno;
		}
	}
	return 0;
}

int pman_mark_single_64bit_syscall(int syscall_id, bool interesting) {
	const int fd = bpf_map__fd(g_state.skel->maps.interesting_syscalls_table_64bit);
	if(bpf_map_update_elem(fd, &syscall_id, &interesting, BPF_ANY) < 0) {
		const int last_errno = errno;
		log_errorf("unable to set interesting syscall at index %d as %d!", syscall_id, interesting);
		return last_errno;
	}
	return 0;
}

static int size_auxiliary_maps(const struct bpf_probe* probe, const uint32_t max_entries) {
	if(bpf_map__set_max_entries(probe->maps.auxiliary_maps, max_entries)) {
		const int last_errno = errno;
		log_errorf("unable to set max entries for 'auxiliary_maps' to %d", max_entries);
		return last_errno;
	}
	/* The probe searches the whole array when a build changed CPU, so it needs the bound. */
	probe->rodata->g_auxmap_pool_entries = max_entries;
	return 0;
}

static int size_counter_maps(const struct bpf_probe* probe, const uint32_t max_entries) {
	if(bpf_map__set_max_entries(probe->maps.counter_maps, max_entries)) {
		log_errorf("unable to set max entries for 'counter_maps' to %d", max_entries);
		return errno;
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/* Here we split maps operations, before and after the loading phase.
 */

/* Whether this kernel accepts the atomics added in 5.12, probed by loading a program that uses
 * one. A version check would be wrong here: distributions backport, and what matters is only
 * whether the verifier takes the opcode.
 */
static bool probe_bpf_atomics(void) {
	/* r1 = 0; *(u64 *)(r10 - 8) = r1; r2 = 1; r0 = cmpxchg(r10 - 8, r0, r2); r0 = 0; exit */
	struct bpf_insn insns[] = {
	        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
	        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_1, .imm = 0},
	        {.code = BPF_STX | BPF_MEM | BPF_DW,
	         .dst_reg = BPF_REG_10,
	         .src_reg = BPF_REG_1,
	         .off = -8},
	        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_2, .imm = 1},
	        {.code = BPF_STX | BPF_ATOMIC | BPF_DW,
	         .dst_reg = BPF_REG_10,
	         .src_reg = BPF_REG_2,
	         .off = -8,
	         .imm = BPF_CMPXCHG},
	        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
	        {.code = BPF_JMP | BPF_EXIT},
	};

	/* The instruction under test, and the only difference between this program and the control
	 * below. */
	const size_t atomic_insn = 4;
	const size_t insn_cnt = sizeof(insns) / sizeof(insns[0]);

	int fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
	                       "auxmap_cas",
	                       "Dual BSD/GPL",
	                       insns,
	                       insn_cnt,
	                       NULL);
	if(fd >= 0) {
		close(fd);
		return true;
	}
	const int atomic_errno = errno;

	/* The load failed, and there is more than one reason it could have: the verifier refuses
	 * the encoding before 5.12, a JIT refuses to compile it where the verifier accepts it
	 * (arm64 took the fetching atomics only in 6.0), or this environment cannot load any BPF
	 * program at all. The errno does not separate them reliably, and the difference matters,
	 * because answering "no" is not a passive answer: it clears the flag *and* rewrites the
	 * cmpxchg out of every program, which on a kernel that can preempt a build leaves
	 * auxmap__claim() racy. Only a kernel that genuinely refuses the opcode may be answered
	 * "no".
	 *
	 * So ask the same question again with the atomic replaced by the plain store the cleared
	 * branch would have executed. Everything else -- program type, license, length, stack use,
	 * absence of maps -- is identical, so if the control loads and the atomic did not, it is
	 * the opcode; if neither loads, it is the environment, and the real load is about to fail
	 * the same way and say so properly. */
	insns[atomic_insn].code = BPF_STX | BPF_MEM | BPF_DW;
	insns[atomic_insn].imm = 0;

	fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
	                   "auxmap_store",
	                   "Dual BSD/GPL",
	                   insns,
	                   insn_cnt,
	                   NULL);
	if(fd < 0) {
		log_msgf(FALCOSECURITY_LOG_SEV_WARNING,
		         "cannot probe for BPF atomics (%s); assuming they are supported. If this "
		         "kernel does not have them, loading the probe will fail",
		         strerror(atomic_errno));
		return true;
	}
	close(fd);

	log_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
	         "no BPF atomics on this kernel (%s)",
	         strerror(atomic_errno));
	return false;
}

/* Tell the probe whether it has atomics, and where it does not, take the cmpxchg out of the
 * programs altogether.
 *
 * The rodata flag alone is not enough. A verifier without the 5.12 atomics rejects
 * `BPF_STX | BPF_ATOMIC` carrying a non-zero imm in a pass that runs before it walks a single
 * instruction -- "BPF_STX uses reserved fields", 0 insns processed -- so it never reaches the
 * branch the flag would have folded, and the whole object fails to load. The instruction has to
 * be absent, not unreachable.
 *
 * Rewriting it as `*(u64 *)(dst + off) = src` is sound because auxmap__claim() holds the only
 * atomic in the driver and it sits on the branch this function has just switched off: with the
 * flag clear that code never runs, and the store is what the other branch does anyway. An atomic
 * with imm == 0 is a bare add, which a pre-5.12 verifier accepts; we emit none, and if one ever
 * appears its load will fail loudly rather than be quietly stripped of its atomicity.
 */
static int prepare_bpf_atomics(const struct bpf_probe* probe) {
	if(probe_bpf_atomics()) {
		probe->rodata->g_bpf_atomics = 1;
		return 0;
	}
	probe->rodata->g_bpf_atomics = 0;

	struct bpf_program* prog;
	uint32_t rewritten = 0;

	bpf_object__for_each_program(prog, probe->obj) {
		const struct bpf_insn* insns = bpf_program__insns(prog);
		const size_t insn_cnt = bpf_program__insn_cnt(prog);
		struct bpf_insn* rewrite = NULL;

		for(size_t i = 0; i < insn_cnt; i++) {
			/* The second word of a 16-byte load carries no opcode, so step over it rather
			 * than reading it as one. */
			if(insns[i].code == (BPF_LD | BPF_IMM | BPF_DW)) {
				i++;
				continue;
			}
			if(BPF_CLASS(insns[i].code) != BPF_STX || BPF_MODE(insns[i].code) != BPF_ATOMIC ||
			   insns[i].imm == 0) {
				continue;
			}
			if(!rewrite) {
				rewrite = malloc(insn_cnt * sizeof(*rewrite));
				if(!rewrite) {
					log_errorf("unable to allocate instructions for '%s'", bpf_program__name(prog));
					return -1;
				}
				memcpy(rewrite, insns, insn_cnt * sizeof(*rewrite));
			}
			rewrite[i].code = BPF_STX | BPF_MEM | BPF_SIZE(insns[i].code);
			rewrite[i].imm = 0;
			rewritten++;
		}

		if(rewrite) {
			const int err = bpf_program__set_insns(prog, rewrite, insn_cnt);
			free(rewrite);
			if(err) {
				log_errorf("unable to replace the atomics in '%s'", bpf_program__name(prog));
				return err;
			}
		}
	}

	log_msgf(FALCOSECURITY_LOG_SEV_WARNING,
	         "no BPF atomics on this kernel: %u instruction(s) rewritten as plain stores. "
	         "Detection will continue to work, but the auxmap claim is no longer atomic, which "
	         "is only safe on a kernel that cannot preempt a build mid-claim",
	         rewritten);
	return 0;
}

int pman_prepare_maps_before_loading() {
	/* Read-only global variables must be set before loading phase. */
	fill_event_params_table();
	fill_ppm_sc_table();
	fill_ia32_to_64_table();
	fill_syscall_sampling_table();
	int err = prepare_bpf_atomics(g_state.skel);
	if(err) {
		return err;
	}

	/* We need to set the entries number for every BPF_MAP_TYPE_ARRAY. The number of entries will be
	 * always equal to the CPUs number, even if some of them are not online.
	 */
	err = err
	              ?: size_auxiliary_maps(g_state.skel,
	                                     (uint32_t)g_state.n_possible_cpus * AUXMAP_POOL_DEPTH);
	err = err ?: size_counter_maps(g_state.skel, g_state.n_possible_cpus);
	return err;
}

#ifdef BPF_ITERATOR_SUPPORT
// Variant of `pman_prepare_maps_before_loading()` used for testing BPF iterator programs support.
int iter_support_probing__prepare_maps_before_loading(struct iter_support_probing_ctx* ctx) {
	int err = prepare_bpf_atomics(ctx->probe);
	err = err ?: size_auxiliary_maps(ctx->probe, 1);
	err = err ?: size_counter_maps(ctx->probe, 1);
	return err;
}
#endif  // BPF_ITERATOR_SUPPORT

int pman_finalize_maps_after_loading() {
	int err;
	struct capture_settings settings = {};
	err = update_capture_settings(&settings);
	if(err != 0) {
		return err;
	}

	/* set bpf global variables. */
	pman_set_snaplen(80);
	pman_set_dropping_mode(false);
	pman_set_sampling_ratio(1);
	pman_set_drop_failed(false);
	pman_set_do_dynamic_snaplen(false);
	pman_set_fullcapture_port_range(0, 0);
	pman_set_statsd_port(PPM_PORT_STATSD);

	/* We have to fill all ours tail tables. */
	fill_interesting_syscalls_table_64bit();
	err = fill_syscalls_tail_table();
	err = err ?: fill_syscall_exit_extra_tail_table();
	return err;
}
