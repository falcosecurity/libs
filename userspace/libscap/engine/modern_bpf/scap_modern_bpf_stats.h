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

typedef enum modern_bpf_kernel_counters_stats {
	MODERN_BPF_N_EVTS = 0,
	MODERN_BPF_N_DROPS_BUFFER_TOTAL,
	MODERN_BPF_N_DROPS_SCRATCH_MAP,
	MODERN_BPF_N_DROPS,
	MODERN_BPF_MAX_KERNEL_COUNTERS_STATS
}modern_bpf_kernel_counters_stats;

extern const char * const modern_bpf_kernel_counters_stats_names[];
