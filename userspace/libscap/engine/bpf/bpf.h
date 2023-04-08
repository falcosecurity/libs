/*
Copyright (C) 2022 The Falco Authors.

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

#pragma once

#include <stdbool.h>
#include "../../ringbuffer/devset.h"
#include "scap_open.h"
#include "attached_prog.h"
#include "scap.h"

//
// ebpf defs
//

#ifndef BPF_PROGS_TAIL_CALLED_MAX
#define BPF_PROGS_TAIL_CALLED_MAX 256
#endif

#define BPF_MAPS_MAX 32

typedef enum bpf_kernel_counters_stats {
	BPF_N_EVTS = 0,
	BPF_N_DROPS_BUFFER_TOTAL,
	BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER,
	BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT,
	BPF_N_DROPS_BUFFER_EXECVE_ENTER,
	BPF_N_DROPS_BUFFER_EXECVE_EXIT,
	BPF_N_DROPS_BUFFER_CONNECT_ENTER,
	BPF_N_DROPS_BUFFER_CONNECT_EXIT,
	BPF_N_DROPS_BUFFER_OPEN_ENTER,
	BPF_N_DROPS_BUFFER_OPEN_EXIT,
	BPF_N_DROPS_BUFFER_DIR_FILE_ENTER,
	BPF_N_DROPS_BUFFER_DIR_FILE_EXIT,
	BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER,
	BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	BPF_N_DROPS_SCRATCH_MAP,
	BPF_N_DROPS_PAGE_FAULTS,
	BPF_N_DROPS_BUG,
	BPF_N_DROPS,
	BPF_MAX_KERNEL_COUNTERS_STATS
}bpf_kernel_counters_stats;

static const char * const bpf_kernel_counters_stats_names[] = {
	[BPF_N_EVTS] = "n_evts",
	[BPF_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[BPF_N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[BPF_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[BPF_N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[BPF_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[BPF_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[BPF_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[BPF_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[BPF_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[BPF_N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[BPF_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[BPF_N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[BPF_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[BPF_N_DROPS_SCRATCH_MAP] = "n_drops_scratch_map",
	[BPF_N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[BPF_N_DROPS_BUG] = "n_drops_bug",
	[BPF_N_DROPS] = "n_drops",
};

enum bpf_libbpf_stats {
	RUN_CNT = 0,
	RUN_TIME_NS,
	AVG_TIME_NS,
	BPF_MAX_LIBBPF_STATS,
};

static const char * const bpf_libbpf_stats_names[] = {
	[RUN_CNT] = ".run_cnt", ///< `bpf_prog_info` run_cnt.
	[RUN_TIME_NS] = ".run_time_ns", ///<`bpf_prog_info` run_time_ns.
	[AVG_TIME_NS] = ".avg_time_ns", ///< Average time spent in bpg program, calculation: run_time_ns / run_cnt.
};

struct bpf_engine
{
	struct scap_device_set m_dev_set;
	size_t m_ncpus;
	char* m_lasterr;

	int m_tail_called_fds[BPF_PROGS_TAIL_CALLED_MAX];
	int m_tail_called_cnt;
	bpf_attached_prog m_attached_progs[BPF_PROG_ATTACHED_MAX];
	/* buffer m_stats holds scap_stats_v2 statistics, static const sized for now,
	 * may be refactored to allow for dynamic allocation in the future
	 * in order to reflect true available stats and not over allocate. */
	scap_stats_v2 m_stats[(BPF_PROG_ATTACHED_MAX * BPF_MAX_LIBBPF_STATS) + BPF_MAX_KERNEL_COUNTERS_STATS];

	int m_bpf_map_fds[BPF_MAPS_MAX];
	int m_bpf_prog_array_map_idx;
	char m_filepath[PATH_MAX];

	/* ELF related */
	int program_fd;
	Elf *elf;
	GElf_Ehdr ehdr;

	interesting_ppm_sc_set curr_sc_set;
	uint64_t m_api_version;
	uint64_t m_schema_version;
	bool capturing;
};
