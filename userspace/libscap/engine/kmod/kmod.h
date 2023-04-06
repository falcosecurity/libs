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

#include <stdint.h>
#include "ringbuffer/devset.h"
#include "scap_open.h"

typedef enum kernel_counters_stats {
	N_EVTS = 0,
	N_DROPS_BUFFER_TOTAL,
	N_DROPS_BUFFER_CLONE_FORK_ENTER,
	N_DROPS_BUFFER_CLONE_FORK_EXIT,
	N_DROPS_BUFFER_EXECVE_ENTER,
	N_DROPS_BUFFER_EXECVE_EXIT,
	N_DROPS_BUFFER_CONNECT_ENTER,
	N_DROPS_BUFFER_CONNECT_EXIT,
	N_DROPS_BUFFER_OPEN_ENTER,
	N_DROPS_BUFFER_OPEN_EXIT,
	N_DROPS_BUFFER_DIR_FILE_ENTER,
	N_DROPS_BUFFER_DIR_FILE_EXIT,
	N_DROPS_BUFFER_OTHER_INTEREST_ENTER,
	N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	N_DROPS_PAGE_FAULTS,
	N_DROPS_BUG,
	N_DROPS,
	N_PREEMPTIONS,
	MAX_KERNEL_COUNTERS_STATS
}kernel_counters_stats;

static const char * const kernel_counters_stats_names[] = {
	[N_EVTS] = "n_evts",
	[N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[N_DROPS_BUG] = "n_drops_bug",
	[N_DROPS] = "n_drops",
	[N_PREEMPTIONS] = "n_preemptions",
};

struct kmod_engine
{
	struct scap_device_set m_dev_set;
	char* m_lasterr;
	interesting_ppm_sc_set curr_sc_set;
	uint64_t m_api_version;
	uint64_t m_schema_version;
	bool capturing;
};
