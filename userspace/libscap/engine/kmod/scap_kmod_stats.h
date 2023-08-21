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

typedef enum kmod_kernel_counters_stats {
	KMOD_N_EVTS = 0,
	KMOD_N_DROPS_BUFFER_TOTAL,
	KMOD_N_DROPS_BUFFER_CLONE_FORK_ENTER,
	KMOD_N_DROPS_BUFFER_CLONE_FORK_EXIT,
	KMOD_N_DROPS_BUFFER_EXECVE_ENTER,
	KMOD_N_DROPS_BUFFER_EXECVE_EXIT,
	KMOD_N_DROPS_BUFFER_CONNECT_ENTER,
	KMOD_N_DROPS_BUFFER_CONNECT_EXIT,
	KMOD_N_DROPS_BUFFER_OPEN_ENTER,
	KMOD_N_DROPS_BUFFER_OPEN_EXIT,
	KMOD_N_DROPS_BUFFER_DIR_FILE_ENTER,
	KMOD_N_DROPS_BUFFER_DIR_FILE_EXIT,
	KMOD_N_DROPS_BUFFER_OTHER_INTEREST_ENTER,
	KMOD_N_DROPS_BUFFER_OTHER_INTEREST_EXIT,
	KMOD_N_DROPS_BUFFER_CLOSE_EXIT,
	KMOD_N_DROPS_BUFFER_PROC_EXIT,
	KMOD_N_DROPS_PAGE_FAULTS,
	KMOD_N_DROPS_BUG,
	KMOD_N_DROPS,
	KMOD_N_PREEMPTIONS,
	KMOD_MAX_KERNEL_COUNTERS_STATS
}kmod_kernel_counters_stats;
