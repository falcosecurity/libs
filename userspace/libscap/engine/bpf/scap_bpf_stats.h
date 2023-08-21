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

#pragma once

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
	BPF_N_DROPS_BUFFER_CLOSE_EXIT,
	BPF_N_DROPS_BUFFER_PROC_EXIT,
	BPF_N_DROPS_SCRATCH_MAP,
	BPF_N_DROPS_PAGE_FAULTS,
	BPF_N_DROPS_BUG,
	BPF_N_DROPS,
	BPF_MAX_KERNEL_COUNTERS_STATS
}bpf_kernel_counters_stats;

enum bpf_libbpf_stats {
	RUN_CNT = 0,
	RUN_TIME_NS,
	AVG_TIME_NS,
	BPF_MAX_LIBBPF_STATS,
};
