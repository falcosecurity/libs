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
#include <libscap/scap_limits.h>
#include <libscap/engine/savefile/scap_reader.h>
#include <libscap/scap_savefile.h>
#include <libscap/strerror.h>

#define READER_BUF_SIZE (1 << 16)  // UINT16_MAX + 1, ie: 65536

#define CHECK_READ_SIZE_ERR(read_size, expected_size, error)                          \
	if(read_size != expected_size) {                                                  \
		return scap_errprintf(                                                        \
		        error,                                                                \
		        0,                                                                    \
		        "expecting %d bytes, read %d at %s, line %d. Is the file truncated?", \
		        (int)expected_size,                                                   \
		        (int)read_size,                                                       \
		        __FILE__,                                                             \
		        __LINE__);                                                            \
	}

#define CHECK_READ_SIZE(read_size, expected_size)                                     \
	if(read_size != expected_size) {                                                  \
		return scap_errprintf(                                                        \
		        handle->m_lasterr,                                                    \
		        0,                                                                    \
		        "expecting %d bytes, read %d at %s, line %d. Is the file truncated?", \
		        (int)expected_size,                                                   \
		        (int)read_size,                                                       \
		        __FILE__,                                                             \
		        __LINE__);                                                            \
	}

#define CHECK_READ_SIZE_WITH_FREE_ERR(alloc_buffer, read_size, expected_size, error)  \
	if(read_size != expected_size) {                                                  \
		free(alloc_buffer);                                                           \
		return scap_errprintf(                                                        \
		        error,                                                                \
		        0,                                                                    \
		        "expecting %d bytes, read %d at %s, line %d. Is the file truncated?", \
		        (int)expected_size,                                                   \
		        (int)read_size,                                                       \
		        __FILE__,                                                             \
		        __LINE__);                                                            \
	}

//
// The following stuff is byte aligned because we save it to disk.
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/*!
  \brief For backward compatibility only
*/
typedef struct scap_ifinfo_ipv4_nolinkspeed {
	uint16_t type;
	uint16_t ifnamelen;
	uint32_t addr;
	uint32_t netmask;
	uint32_t bcast;
	char ifname[SCAP_MAX_PATH_SIZE];
} scap_ifinfo_ipv4_nolinkspeed;

/*!
  \brief For backword compatibility only
*/
typedef struct scap_ifinfo_ipv6_nolinkspeed {
	uint16_t type;
	uint16_t ifnamelen;
	char addr[SCAP_IPV6_ADDR_LEN];
	char netmask[SCAP_IPV6_ADDR_LEN];
	char bcast[SCAP_IPV6_ADDR_LEN];
	char ifname[SCAP_MAX_PATH_SIZE];
} scap_ifinfo_ipv6_nolinkspeed;

#pragma pack(pop)

struct scap_platform;

struct savefile_engine {
	char* m_lasterr;
	scap_reader_t* m_reader;
	block_header m_last_block_header;
	bool m_use_last_block_header;
	char* m_reader_evt_buf;
	size_t m_reader_evt_buf_size;
	uint32_t m_last_evt_dump_flags;
	struct scap_platform* m_platform;
	// Used by the scap-file converter
	char* m_new_evt;
	char* m_to_convert_evt;
	struct scap_convert_buffer* m_converter_buf;
};
