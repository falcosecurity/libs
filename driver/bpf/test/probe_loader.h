/*
Copyright (C) 2021 The Falco Authors.

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

#ifndef _TEST_PROBE_LOADER_H
#define _TEST_PROBE_LOADER_H

#include <bpf/libbpf.h>

#include "ppm_fillers.h"
#include "ppm_events_public.h"

// The defines here are so that when we include driver/bpf/types.h
// we pretend to be the kernel so that we write internal data types
// for writing the data fixtures for our tests.
// We only support the raw tracepoints implementation now since we can
// only hook into them at the moment.
#define __KERNEL__
#define TASK_COMM_LEN 16
#define BPF_SUPPORTS_RAW_TRACEPOINTS
#include "../types.h"

// pt_regs is an internal data structure
// it is copied here directly to avoid a dependency with kernel sources
// for this userspace code
struct pt_regs
{
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

extern const struct ppm_event_entry g_ppm_events[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

extern char *g_probe_path;

int do_test_single_filler(const char *filler_name, struct sys_exit_args ctx, enum ppm_event_type event_type, char *scratch);

#ifdef BPF_TEST_DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

#endif // _TEST_PROBE_LOADER_H