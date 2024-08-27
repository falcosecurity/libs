// SPDX-License-Identifier: Apache-2.0
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

#include <stdint.h>
#include <stddef.h>

#include <sys/mman.h>
#include <unistd.h>
#define INVALID_FD (-1)
#define INVALID_MAPPING MAP_FAILED

#include <libscap/scap_assert.h>

//
// Read buffer timeout constants
//
#define BUFFER_EMPTY_WAIT_TIME_US_START 500
#define BUFFER_EMPTY_WAIT_TIME_US_MAX (30 * 1000)
#define BUFFER_EMPTY_THRESHOLD_B 20000

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
