#ifndef __TEST_FILLERS_H
#define __TEST_FILLERS_H

#include <bpf/libbpf.h>

#include "ppm_fillers.h"
#include "ppm_events_public.h"
#include "../types.h"

#define STRINGIZE(x) #x

#ifndef PROBE_PATH
#define PROBE_PATH "driver/bpf/btf-probe.o"
#endif

// todo(fntlnz): can use the one in types.h directly?
struct filler_data
{
	void *ctx;
	struct sysdig_bpf_settings *settings;
	struct sysdig_bpf_per_cpu_state *state;
	char *tmp_scratch;
	const struct ppm_event_info *evt;
	const struct ppm_event_entry *filler_info;
	bool curarg_already_on_frame;
	char *buf;
	int fd;
};

// drivers common external interface for syscall<->ppm interfacing/routing
extern const struct ppm_event_entry g_ppm_events[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

int do_test_single_filler(__u32 *retval, const char *filler_name, struct filler_data data);

#ifdef BPF_TEST_DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

#endif // _TEST_FILLERS_H