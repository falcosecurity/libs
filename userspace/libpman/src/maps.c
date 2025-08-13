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
#include <libscap/scap.h>

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

int pman_get_capture_settings(struct capture_settings* settings) {
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int ret;
	uint32_t key = 0;
	int fd = bpf_map__fd(g_state.skel->maps.capture_settings);
	if(fd <= 0) {
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get capture_settings map fd!");
		pman_print_error((const char*)error_message);
		return errno;
	}
	if((ret = bpf_map_lookup_elem(fd, &key, settings)) != 0) {
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get capture_settings!");
		pman_print_error((const char*)error_message);
	}

	return ret;
}

int pman_update_capture_settings(struct capture_settings* settings) {
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int ret;
	int fd = bpf_map__fd(g_state.skel->maps.capture_settings);
	if(fd <= 0) {
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get capture_settings map fd!");
		pman_print_error((const char*)error_message);
		return errno;
	}
	uint32_t key = 0;
	if((ret = bpf_map_update_elem(fd, &key, settings, BPF_ANY)) != 0) {
		snprintf(error_message,
		         MAX_ERROR_MESSAGE_LEN,
		         "unable to initialize capture_settings map!");
		pman_print_error((const char*)error_message);
	}

	return ret;
}

void pman_set_snaplen(uint32_t desired_snaplen) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.snaplen = desired_snaplen;
	pman_update_capture_settings(&settings);
}

void pman_set_boot_time(uint64_t boot_time) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.boot_time = boot_time;
	pman_update_capture_settings(&settings);
}

void pman_set_dropping_mode(bool value) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.dropping_mode = value;
	pman_update_capture_settings(&settings);
}

void pman_set_sampling_ratio(uint32_t value) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.sampling_ratio = value;
	pman_update_capture_settings(&settings);
}

void pman_set_drop_failed(bool drop_failed) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.drop_failed = drop_failed;
	pman_update_capture_settings(&settings);
}

void pman_set_do_dynamic_snaplen(bool do_dynamic_snaplen) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.do_dynamic_snaplen = do_dynamic_snaplen;
	pman_update_capture_settings(&settings);
}

void pman_set_fullcapture_port_range(uint16_t range_start, uint16_t range_end) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.fullcapture_port_range_start = range_start;
	settings.fullcapture_port_range_end = range_end;
	pman_update_capture_settings(&settings);
}

void pman_set_statsd_port(uint16_t statsd_port) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.statsd_port = statsd_port;
	pman_update_capture_settings(&settings);
}

void pman_set_scap_tid(int32_t scap_tid) {
	struct capture_settings settings;
	if(pman_get_capture_settings(&settings) != 0) {
		return;
	}
	settings.scap_tid = scap_tid;
	pman_update_capture_settings(&settings);
}

void pman_fill_syscall_sampling_table() {
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

void pman_fill_ia32_to_64_table() {
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
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct bpf_program* bpf_prog = NULL;
	int bpf_prog_fd = 0;

	bpf_prog = bpf_object__find_program_by_name(g_state.skel->obj, bpf_prog_name);
	if(!bpf_prog) {
		snprintf(error_message,
		         MAX_ERROR_MESSAGE_LEN,
		         "unable to find BPF program '%s'",
		         bpf_prog_name);
		pman_print_msg(FALCOSECURITY_LOG_SEV_DEBUG, (const char*)error_message);

		/*
		 * It's not a hard failure, as programs could be excluded from the
		 * build. There is no need to close the file descriptor yet, so return
		 * success.
		 */
		return 0;
	}

	bpf_prog_fd = bpf_program__fd(bpf_prog);
	if(bpf_prog_fd <= 0) {
		snprintf(error_message,
		         MAX_ERROR_MESSAGE_LEN,
		         "unable to get the fd for BPF program '%s'",
		         bpf_prog_name);
		pman_print_error((const char*)error_message);
		goto clean_add_program_to_tail_table;
	}

	if(bpf_map_update_elem(tail_table_fd, &key, &bpf_prog_fd, BPF_ANY)) {
		snprintf(error_message,
		         MAX_ERROR_MESSAGE_LEN,
		         "unable to update the tail table with BPF program '%s'",
		         bpf_prog_name);
		pman_print_error((const char*)error_message);
		goto clean_add_program_to_tail_table;
	}
	return 0;

clean_add_program_to_tail_table:
	close(bpf_prog_fd);
	return errno;
}

int pman_fill_syscalls_tail_table() {
	int syscall_enter_tail_table_fd = 0;
	int syscall_exit_tail_table_fd = 0;
	int enter_event_type = 0;
	int exit_event_type = 0;

	syscall_enter_tail_table_fd = bpf_map__fd(g_state.skel->maps.syscall_enter_tail_table);
	if(syscall_enter_tail_table_fd <= 0) {
		pman_print_error("unable to get the syscall enter tail table");
		return errno;
	}

	syscall_exit_tail_table_fd = bpf_map__fd(g_state.skel->maps.syscall_exit_tail_table);
	if(syscall_exit_tail_table_fd <= 0) {
		pman_print_error("unable to get the syscall exit tail table");
		return errno;
	}

	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++) {
		/* Get event type from `g_syscall_table` */
		enter_event_type = g_syscall_table[syscall_id].enter_event_type;
		exit_event_type = g_syscall_table[syscall_id].exit_event_type;

		/* If the syscall is generic, the exit_event would be `0`, so
		 * `PPME_GENERIC_E` but for the exit_event we want `PPME_GENERIC_X`
		 * that is `1`, so we patch it on the fly, otherwise the exit_event
		 * will be associated with the wrong bpf program, `generic_e` instead
		 * of `generic_x`.
		 */
		if(exit_event_type == PPME_GENERIC_E) {
			exit_event_type = PPME_GENERIC_X;
		}

		/* At the end of the work, we should always have a corresponding bpf program for every
		 * event. Until we miss some syscalls, this is not true so we manage these cases as generic
		 * events. We need to remove this workaround when all syscalls will be implemented.
		 */
		if(enter_event_type != PPME_SYSCALL_OPEN_E && enter_event_type != PPME_SYSCALL_OPENAT_2_E &&
		   enter_event_type != PPME_SYSCALL_OPENAT2_E && enter_event_type != PPME_SYSCALL_CREAT_E &&
		   enter_event_type != PPME_SOCKET_CONNECT_E) {
			const event_prog_t* enter_prog =
			        (const event_prog_t*)&event_prog_table[enter_event_type];
			const char* enter_prog_name = enter_prog->name;
			if(!enter_prog_name) {
				enter_prog = (const event_prog_t*)&event_prog_table[PPME_GENERIC_E];
				enter_prog_name = enter_prog->name;
			}

			/* No programs other tail raw tracepoints are currently tail-called by the sys_enter
			 * dispatcher. */
			if(enter_prog->prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT) {
				if(add_bpf_program_to_tail_table(syscall_enter_tail_table_fd,
				                                 enter_prog_name,
				                                 syscall_id)) {
					goto clean_fill_syscalls_tail_table;
				}
			}
		}

		const event_prog_t* exit_prog = (const event_prog_t*)&event_prog_table[exit_event_type];
		const char* exit_prog_name = exit_prog->name;
		if(!exit_prog_name) {
			exit_prog = (const event_prog_t*)&event_prog_table[PPME_GENERIC_X];
			exit_prog_name = exit_prog->name;
		}

		/* No programs other tail raw tracepoints are currently tail-called by the sys_exit
		 * dispatcher. */
		if(exit_prog->prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT) {
			if(add_bpf_program_to_tail_table(syscall_exit_tail_table_fd,
			                                 exit_prog_name,
			                                 syscall_id)) {
				goto clean_fill_syscalls_tail_table;
			}
		}
	}
	return 0;

clean_fill_syscalls_tail_table:
	close(syscall_enter_tail_table_fd);
	close(syscall_exit_tail_table_fd);
	return errno;
}

int pman_fill_syscall_exit_extra_tail_table() {
	int extra_sys_exit_tail_table_fd =
	        bpf_map__fd(g_state.skel->maps.syscall_exit_extra_tail_table);
	if(extra_sys_exit_tail_table_fd <= 0) {
		pman_print_error("unable to get the extra sys exit tail table");
		return errno;
	}

	const char* tail_prog_name = NULL;
	for(int j = 0; j < SYS_EXIT_EXTRA_CODE_MAX; j++) {
		tail_prog_name = sys_exit_extra_event_names[j];

		if(!tail_prog_name) {
			pman_print_error("unknown entry in the extra sys exit tail table");
			return -1;
		}

		if(add_bpf_program_to_tail_table(extra_sys_exit_tail_table_fd, tail_prog_name, j)) {
			close(extra_sys_exit_tail_table_fd);
			return errno;
		}
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

int pman_fill_interesting_syscalls_table_64bit() {
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int fd = bpf_map__fd(g_state.skel->maps.interesting_syscalls_table_64bit);
	for(uint32_t i = 0; i < SYSCALL_TABLE_SIZE; i++) {
		const bool interesting = false;
		if(bpf_map_update_elem(fd, &i, &interesting, BPF_ANY) < 0) {
			snprintf(error_message,
			         MAX_ERROR_MESSAGE_LEN,
			         "unable to initialize interesting syscall table at index %d!",
			         i);
			pman_print_error((const char*)error_message);
			return errno;
		}
	}
	return 0;
}

int pman_mark_single_64bit_syscall(int syscall_id, bool interesting) {
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int fd = bpf_map__fd(g_state.skel->maps.interesting_syscalls_table_64bit);
	if(bpf_map_update_elem(fd, &syscall_id, &interesting, BPF_ANY) < 0) {
		snprintf(error_message,
		         MAX_ERROR_MESSAGE_LEN,
		         "unable to set interesting syscall at index %d as %d!",
		         syscall_id,
		         interesting);
		pman_print_error((const char*)error_message);
		return errno;
	}
	return 0;
}

static int size_auxiliary_maps() {
	/* We always allocate auxiliary maps from all the CPUs, even if some of them are not online. */
	if(bpf_map__set_max_entries(g_state.skel->maps.auxiliary_maps, g_state.n_possible_cpus)) {
		pman_print_error("unable to set max entries for 'auxiliary_maps'");
		return errno;
	}
	return 0;
}

static int size_counter_maps() {
	/* We always allocate counter maps from all the CPUs, even if some of them are not online. */
	if(bpf_map__set_max_entries(g_state.skel->maps.counter_maps, g_state.n_possible_cpus)) {
		pman_print_error("unable to set max entries for 'counter_maps'");
		return errno;
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/* Here we split maps operations, before and after the loading phase.
 */

int pman_prepare_maps_before_loading() {
	int err;

	/* Read-only global variables must be set before loading phase. */
	fill_event_params_table();
	fill_ppm_sc_table();
	pman_fill_ia32_to_64_table();
	pman_fill_syscall_sampling_table();

	/* We need to set the entries number for every BPF_MAP_TYPE_ARRAY
	 * The number of entries will be always equal to the CPUs number.
	 */
	err = size_auxiliary_maps();
	err = err ?: size_counter_maps();
	return err;
}

int pman_finalize_maps_after_loading() {
	int err;
	struct capture_settings settings = {};
	err = pman_update_capture_settings(&settings);
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
	pman_fill_interesting_syscalls_table_64bit();
	err = pman_fill_syscalls_tail_table();
	err = err ?: pman_fill_syscall_exit_extra_tail_table();
	return err;
}
