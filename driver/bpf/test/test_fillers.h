#ifndef __TEST_FILLERS_H
#define __TEST_FILLERS_H

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

#ifndef PROBE_PATH
#define PROBE_PATH "driver/bpf/btf-probe.o" // todo(fntlnz): check if this default works
#endif

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

// todo(fntlnz): are these needed now that we use bpf_prog_test_run ?
// drivers common external interface for syscall<->ppm interfacing/routing
extern const struct ppm_event_entry g_ppm_events[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

int do_test_single_filler(const char *filler_name, struct filler_data data, char *scratch);

#ifdef BPF_TEST_DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

#endif // _TEST_FILLERS_H