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
#include <stddef.h>

#include <sys/mman.h>
#include <unistd.h>
#define INVALID_FD (-1)
#define INVALID_MAPPING MAP_FAILED

#include "scap_assert.h"
#include "scap.h"

//
// Read buffer timeout constants
//
#define BUFFER_EMPTY_WAIT_TIME_US_START 500
#define BUFFER_EMPTY_WAIT_TIME_US_MAX (30 * 1000)
#define BUFFER_EMPTY_THRESHOLD_B 20000

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
	KMOD_N_DROPS_PAGE_FAULTS,
	KMOD_N_DROPS_BUG,
	KMOD_N_DROPS,
	KMOD_N_PREEMPTIONS,
	KMOD_MAX_KERNEL_COUNTERS_STATS
}kmod_kernel_counters_stats;

static const char * const kmod_kernel_counters_stats_names[] = {
	[KMOD_N_EVTS] = "n_evts",
	[KMOD_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[KMOD_N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[KMOD_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[KMOD_N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[KMOD_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[KMOD_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[KMOD_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[KMOD_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[KMOD_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[KMOD_N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[KMOD_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[KMOD_N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[KMOD_N_DROPS_BUG] = "n_drops_bug",
	[KMOD_N_DROPS] = "n_drops",
	[KMOD_N_PREEMPTIONS] = "n_preemptions",
};

typedef enum udig_counters_stats {
	UDIG_N_EVTS = 0,
	UDIG_N_DROPS_BUFFER_TOTAL,
	UDIG_N_DROPS_PAGE_FAULTS,
	UDIG_N_DROPS,
	UDIG_N_PREEMPTIONS,
	UDIG_MAX_COUNTERS_STATS,
}udig_counters_stats;

static const char * const udig_counters_stats_names[] = {
	[UDIG_N_EVTS] = "n_evts",
	[UDIG_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[UDIG_N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[UDIG_N_DROPS] = "n_drops",
	[UDIG_N_PREEMPTIONS] = "n_drops_preemptions",
};

// MAX of KMOD_MAX_KERNEL_COUNTERS_STATS and UDIG_MAX_COUNTERS_STATS
#define MAX_KMOD_UDIG_COUNTERS_STATS KMOD_MAX_KERNEL_COUNTERS_STATS

struct ppm_ring_buffer_info;
struct udig_ring_buffer_status;
//
// The device descriptor
//
typedef struct scap_device
{
	int m_fd;
	int m_bufinfo_fd; // used by udig
	char* m_buffer;
	unsigned long m_buffer_size;
	unsigned long m_mmap_size; // generally 2 * m_buffer_size, but bpf does weird things
	uint32_t m_lastreadsize;
	char* m_sn_next_event; // Pointer to the next event available for scap_next
	uint32_t m_sn_len; // Number of bytes available in the buffer pointed by m_sn_next_event
	union
	{
		// Anonymous struct with ppm stuff
		struct
		{
			struct ppm_ring_buffer_info* m_bufinfo;
			int m_bufinfo_size;
			struct udig_ring_buffer_status* m_bufstatus; // used by udig
		};
	};
} scap_device;

struct scap_device_set
{
	scap_device* m_devs;
	uint32_t m_ndevs;
	uint64_t m_buffer_empty_wait_time_us;
	char* m_lasterr;
	scap_stats_v2 m_stats[MAX_KMOD_UDIG_COUNTERS_STATS]; // used for scap_stats_v2 in kmod and udig
};

int32_t devset_init(struct scap_device_set *devset, size_t num_devs, char *lasterr);
void devset_close_device(struct scap_device *dev);
void devset_free(struct scap_device_set *devset);

static inline void devset_munmap(void* addr, size_t size)
{
	if(addr != INVALID_MAPPING)
	{
		int ret = munmap(addr, size);
		ASSERT(ret == 0);
		(void) ret;
	}
}

static inline void devset_close(int fd)
{
	if(fd != INVALID_FD)
	{
		close(fd);
	}
}
