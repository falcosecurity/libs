// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <driver/ppm_events_public.h>
#include <driver/feature_gates.h>
#include <bpf/libbpf.h>

typedef struct {
	char* name;
	char* kernel_symbol;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type attach_type;
} ia32_event_prog_t;

// Maximum number of ia32 variants to be tried for each event
#define MAX_IA32_VARIANTS 2

typedef struct event_prog_t {
	char* name;
	enum bpf_prog_type prog_type;
	enum bpf_func_id feat;
} event_prog_t;

// Maximum number of programs to be tried (requiring bpf feat checks) for each event
#define MAX_FEATURE_CHECKS 3

typedef struct {
	event_prog_t prog_list[MAX_FEATURE_CHECKS];
	ia32_event_prog_t ia32_prog_list[MAX_IA32_VARIANTS];
} ttm_event_prog_lists;

enum ttm_code {
	TTM_CONNECT = 0,
	TTM_CREAT = 1,
	TTM_OPEN = 2,
	TTM_OPENAT = 3,
	TTM_OPENAT2 = 4,
	TTM_SOCKETCALL = 5,
	TTM_MAX = 6,
};

extern ttm_event_prog_lists ttm_event_prog_table[TTM_MAX];

// Defined in events_prog_names.c
extern event_prog_t event_prog_table[PPM_EVENT_MAX][MAX_FEATURE_CHECKS];
