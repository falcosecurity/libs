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
	enum bpf_func_id feat;
} event_prog_t;

// Maximum number of programs to be tried (requiring bpf feat checks) for each event
#define MAX_FEATURE_CHECKS 3

// Defined in events_prog_names.c
extern event_prog_t event_prog_table[PPM_EVENT_MAX][MAX_FEATURE_CHECKS];
