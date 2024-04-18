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
#include "events_prog_names.h"
#include <libscap/scap.h>

extern const struct ppm_event_info g_event_info[PPM_EVENT_MAX];
extern const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];
extern const int g_ia32_64_map[];

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/// TODO: in a future optimization we can think to remove this table,
/// defining macros for `nparams` and directly use them inside bpf
/// programs instead of reading from a map.
static void fill_event_params_table()
{
	uint8_t nparams_event = 0;

	for(int j = 0; j < PPM_EVENT_MAX; ++j)
	{
		nparams_event = (uint8_t)g_event_info[j].nparams;
		g_state.skel->rodata->g_event_params_table[j] = nparams_event;
	}
}

static void fill_ppm_sc_table()
{
	for(int j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		g_state.skel->rodata->g_ppm_sc_table[j] = (uint16_t)g_syscall_table[j].ppm_sc;
	}
}

uint64_t pman_get_probe_api_ver()
{
	return g_state.skel->rodata->probe_api_ver;
}

uint64_t pman_get_probe_schema_ver()
{
	return g_state.skel->rodata->probe_schema_var;
}

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/*=============================== BPF GLOBAL VARIABLES ===============================*/

void pman_set_snaplen(uint32_t desired_snaplen)
{
	g_state.skel->bss->g_settings.snaplen = desired_snaplen;
}

void pman_set_boot_time(uint64_t boot_time)
{
	g_state.skel->bss->g_settings.boot_time = boot_time;
}

void pman_set_dropping_mode(bool value)
{
	g_state.skel->bss->g_settings.dropping_mode = value;
}

void pman_set_sampling_ratio(uint32_t value)
{
	g_state.skel->bss->g_settings.sampling_ratio = value;
}

void pman_set_drop_failed(bool drop_failed)
{
	g_state.skel->bss->g_settings.drop_failed = drop_failed;
}

void pman_set_do_dynamic_snaplen(bool do_dynamic_snaplen)
{
	g_state.skel->bss->g_settings.do_dynamic_snaplen = do_dynamic_snaplen;
}

void pman_set_fullcapture_port_range(uint16_t range_start, uint16_t range_end)
{
	g_state.skel->bss->g_settings.fullcapture_port_range_start = range_start;
	g_state.skel->bss->g_settings.fullcapture_port_range_end = range_end;
}

void pman_set_statsd_port(uint16_t statsd_port)
{
	g_state.skel->bss->g_settings.statsd_port = statsd_port;
}

void pman_mark_single_64bit_syscall(int intersting_syscall_id, bool interesting)
{
	g_state.skel->bss->g_64bit_interesting_syscalls_table[intersting_syscall_id] = interesting;
}

void pman_fill_syscall_sampling_table()
{
	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++)
	{
		if(g_syscall_table[syscall_id].flags & UF_NEVER_DROP)
		{
			g_state.skel->bss->g_64bit_sampling_syscall_table[syscall_id] = UF_NEVER_DROP;
			continue;
		}

		/* Syscalls with `g_syscall_table[syscall_id].flags == UF_NONE` are the generic ones */
		if(g_syscall_table[syscall_id].flags & UF_ALWAYS_DROP || g_syscall_table[syscall_id].flags == UF_NONE)
		{
			g_state.skel->bss->g_64bit_sampling_syscall_table[syscall_id] = UF_ALWAYS_DROP;
			continue;
		}

		if(g_syscall_table[syscall_id].flags & UF_USED)
		{
			g_state.skel->bss->g_64bit_sampling_syscall_table[syscall_id] = 0;
			continue;
		}
	}
}

void pman_fill_syscall_tracepoint_table()
{
	/* Right now these are the only 2 tracepoints involved in the dropping logic. We need to add them here */
	g_state.skel->bss->g_64bit_sampling_tracepoint_table[PPME_PROCEXIT_1_E] = UF_NEVER_DROP;
	g_state.skel->bss->g_64bit_sampling_tracepoint_table[PPME_SCHEDSWITCH_6_E] = 0;
	g_state.skel->bss->g_64bit_sampling_tracepoint_table[PPME_PAGE_FAULT_E] = UF_ALWAYS_DROP;
	g_state.skel->bss->g_64bit_sampling_tracepoint_table[PPME_SIGNALDELIVER_E] = UF_ALWAYS_DROP;
}

void pman_fill_ia32_to_64_table()
{
	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++)
	{
		// Note: we will map all syscalls from the upper limit of the ia32 table
		// up to SYSCALL_TABLE_SIZE to 0 (because they are not set in the g_ia32_64_map).
		// 0 is read on x86_64; this is not a problem though because
		// we will never receive a 32bit syscall above the upper limit, since it won't be existent.
		const int x64_val = g_ia32_64_map[syscall_id];
		g_state.skel->bss->g_ia32_to_64_table[syscall_id] = x64_val;
	}
}


/*=============================== BPF GLOBAL VARIABLES ===============================*/

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

static int add_bpf_program_to_tail_table(int tail_table_fd, const char* bpf_prog_name, int key)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct bpf_program* bpf_prog = NULL;
	int bpf_prog_fd = 0;

	bpf_prog = bpf_object__find_program_by_name(g_state.skel->obj, bpf_prog_name);
	if(!bpf_prog)
	{
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to find BPF program '%s'", bpf_prog_name);
		pman_print_msg(FALCOSECURITY_LOG_SEV_DEBUG, (const char*)error_message);

		/*
		 * It's not a hard failure, as programs could be excluded from the
		 * build. There is no need to close the file descriptor yet, so return
		 * success.
		 */
		return 0;
	}

	bpf_prog_fd = bpf_program__fd(bpf_prog);
	if(bpf_prog_fd <= 0)
	{
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to get the fd for BPF program '%s'", bpf_prog_name);
		pman_print_error((const char*)error_message);
		goto clean_add_program_to_tail_table;
	}

	if(bpf_map_update_elem(tail_table_fd, &key, &bpf_prog_fd, BPF_ANY))
	{
		snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unable to update the tail table with BPF program '%s'", bpf_prog_name);
		pman_print_error((const char*)error_message);
		goto clean_add_program_to_tail_table;
	}
	return 0;

clean_add_program_to_tail_table:
	close(bpf_prog_fd);
	return errno;
}

int pman_fill_syscalls_tail_table()
{
	int syscall_enter_tail_table_fd = 0;
	int syscall_exit_tail_table_fd = 0;
	int enter_event_type = 0;
	int exit_event_type = 0;
	const char* enter_prog_name;
	const char* exit_prog_name;

	syscall_enter_tail_table_fd = bpf_map__fd(g_state.skel->maps.syscall_enter_tail_table);
	if(syscall_enter_tail_table_fd <= 0)
	{
		pman_print_error("unable to get the syscall enter tail table");
		return errno;
	}

	syscall_exit_tail_table_fd = bpf_map__fd(g_state.skel->maps.syscall_exit_tail_table);
	if(syscall_exit_tail_table_fd <= 0)
	{
		pman_print_error("unable to get the syscall exit tail table");
		return errno;
	}

	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++)
	{

		/* Get event type from `g_syscall_table` */
		enter_event_type = g_syscall_table[syscall_id].enter_event_type;
		exit_event_type = g_syscall_table[syscall_id].exit_event_type;

		/* If the syscall is generic, the exit_event would be `0`, so
		 * `PPME_GENERIC_E` but for the exit_event we want `PPME_GENERIC_X`
		 * that is `1`, so we patch it on the fly, otherwise the exit_event
		 * will be associated with the wrong bpf program, `generic_e` instead
		 * of `generic_x`.
		 */
		if(exit_event_type == PPME_GENERIC_E)
		{
			exit_event_type = PPME_GENERIC_X;
		}

		/* At the end of the work, we should always have a corresponding bpf program for every event.
		 * Until we miss some syscalls, this is not true so we manage these cases as generic events.
		 * We need to remove this workaround when all syscalls will be implemented.
		 */
		enter_prog_name = event_prog_names[enter_event_type];
		exit_prog_name = event_prog_names[exit_event_type];

		if(!enter_prog_name)
		{
			enter_prog_name = event_prog_names[PPME_GENERIC_E];
		}

		if(!exit_prog_name)
		{
			exit_prog_name = event_prog_names[PPME_GENERIC_X];
		}

		if(add_bpf_program_to_tail_table(syscall_enter_tail_table_fd, enter_prog_name, syscall_id))
		{
			goto clean_fill_syscalls_tail_table;
		}

		if(add_bpf_program_to_tail_table(syscall_exit_tail_table_fd, exit_prog_name, syscall_id))
		{
			goto clean_fill_syscalls_tail_table;
		}
	}
	return 0;

clean_fill_syscalls_tail_table:
	close(syscall_enter_tail_table_fd);
	close(syscall_exit_tail_table_fd);
	return errno;
}

int pman_fill_extra_event_prog_tail_table()
{
	int extra_event_prog_tail_table_fd = 0;
	const char* tail_prog_name;

	extra_event_prog_tail_table_fd = bpf_map__fd(g_state.skel->maps.extra_event_prog_tail_table);
	if(extra_event_prog_tail_table_fd <= 0)
	{
		pman_print_error("unable to get the extra event programs tail table");
		return errno;
	}

	for(int j = 0; j < TAIL_EXTRA_EVENT_PROG_MAX; j++)
	{
		tail_prog_name = extra_event_prog_names[j];

		if(!tail_prog_name)
		{
			continue;
		}

		if(add_bpf_program_to_tail_table(extra_event_prog_tail_table_fd, tail_prog_name, j))
		{
			close(extra_event_prog_tail_table_fd);
			return errno;
		}
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

static int size_auxiliary_maps()
{
	/* We always allocate auxiliary maps from all the CPUs, even if some of them are not online. */
	if(bpf_map__set_max_entries(g_state.skel->maps.auxiliary_maps, g_state.n_possible_cpus))
	{
		pman_print_error("unable to set max entries for 'auxiliary_maps'");
		return errno;
	}
	return 0;
}

static int size_counter_maps()
{
	/* We always allocate counter maps from all the CPUs, even if some of them are not online. */
	if(bpf_map__set_max_entries(g_state.skel->maps.counter_maps, g_state.n_possible_cpus))
	{
		pman_print_error(" unable to set max entries for 'counter_maps'");
		return errno;
	}
	return 0;
}

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/* Here we split maps operations, before and after the loading phase.
 */

int pman_prepare_maps_before_loading()
{
	int err;

	/* Read-only global variables must be set before loading phase. */
	fill_event_params_table();
	fill_ppm_sc_table();

	/* We need to set the entries number for every BPF_MAP_TYPE_ARRAY
	 * The number of entries will be always equal to the CPUs number.
	 */
	err = size_auxiliary_maps();
	err = err ?: size_counter_maps();
	return err;
}

int pman_finalize_maps_after_loading()
{
	int err;

	/* set bpf global variables. */
	pman_set_snaplen(80);
	pman_set_dropping_mode(false);
	pman_set_sampling_ratio(1);
	pman_set_drop_failed(false);
	pman_set_do_dynamic_snaplen(false);
	pman_set_fullcapture_port_range(0, 0);
	pman_set_statsd_port(PPM_PORT_STATSD);

	/* We have to fill all ours tail tables. */
	pman_fill_syscall_sampling_table();
	pman_fill_syscall_tracepoint_table();
	pman_fill_ia32_to_64_table();
	err = pman_fill_syscalls_tail_table();
	err = err ?: pman_fill_extra_event_prog_tail_table();
	return err;
}
