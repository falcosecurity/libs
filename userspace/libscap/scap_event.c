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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif // _WIN32

#include "scap.h"
#include "scap-int.h"

//
// Get the event info table
//
const struct ppm_event_info* scap_get_event_info_table()
{
	ASSERT(validate_info_table_size());
	return g_event_info;
}

//
// Get the syscall info table
//
const struct ppm_syscall_desc* scap_get_syscall_info_table()
{
	return g_syscall_info_table;
}

uint32_t scap_event_getlen(scap_evt* e)
{
	return e->len;
}

uint64_t scap_event_get_num(scap_t* handle)
{
	return handle->m_evtcnt;
}

void scap_event_reset_count(scap_t* handle)
{
	handle->m_evtcnt = 0;
}

uint64_t scap_event_get_ts(scap_evt* e)
{
	return e->ts;
}

#ifdef PPM_ENABLE_SENTINEL
uint32_t scap_event_get_sentinel_begin(scap_evt* e)
{
	return e->sentinel_begin;
}
#endif

const struct ppm_event_info* scap_event_getinfo(scap_evt* e)
{
	return &(g_event_info[e->type]);
}

uint32_t scap_event_has_large_payload(const scap_evt* e)
{
	return (g_event_info[e->type].flags & EF_LARGE_PAYLOAD) != 0;
}

uint32_t scap_event_decode_params(const scap_evt *e, struct scap_sized_buffer *params)
{
	char *len_buf = (char*)e + sizeof(struct ppm_evt_hdr);
	char *param_buf = len_buf;
	uint32_t is_large = scap_event_has_large_payload(e);
	uint32_t param_size_32;
	uint16_t param_size_16;

	const struct ppm_event_info* event_info = &(g_event_info[e->type]);
	
	// If we're reading a capture created with a newer version, it may contain
	// new parameters. If instead we're reading an older version, the current
	// event table entry may contain new parameters.
	// Use the minimum between the two values.
	uint32_t n = event_info->nparams < e->nparams ? event_info->nparams : e->nparams;

	if(is_large)
	{
		param_buf += sizeof(uint32_t) * e->nparams;
	} else
	{
		param_buf += sizeof(uint16_t) * e->nparams;
	}

	for(size_t i = 0; i < n; i++) {
		if(is_large)
		{
			memcpy(&param_size_32, len_buf, sizeof(uint32_t));
			params[i].size = param_size_32;
			len_buf += sizeof(uint32_t);
		} else
		{
			memcpy(&param_size_16, len_buf, sizeof(uint16_t));
			params[i].size = param_size_16;
			len_buf += sizeof(uint16_t);
		}

		params[i].buf = param_buf;
		param_buf += params[i].size;
	}

	return n;
}
