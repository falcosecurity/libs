#pragma once

#include <stdbool.h>
#include "../../../../driver/ppm_events_public.h"

struct scap;

struct modern_bpf_engine
{
	bool m_syscalls_of_interest[SYSCALL_TABLE_SIZE];
	size_t m_num_cpus;
	char* m_lasterr;
};

#define SCAP_HANDLE_T struct modern_bpf_engine
