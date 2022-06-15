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

#include <endian.h>
#include <stdbool.h>

typedef enum scap_swap_endian
{
	SCAP_NATIVE_ENDIAN = false,
	SCAP_SWAP_ENDIAN = true
} scap_swap_endian;

// inline void scap_reader_be_block_header_toh(scap_reader_t *r, block_header *bh)
#define scap_reader_be_block_header_toh(r, bh)                                    \
	{                                                                         \
		if(r->m_swap_endian)                                              \
		{                                                                 \
			bh->block_type = be32toh(bh->block_type);                 \
			bh->block_total_length = be32toh(bh->block_total_length); \
		}                                                                 \
	}

#define scap_reader_be16toh(r, u)         \
	{                                 \
		if(r->m_swap_endian)      \
		{                         \
			*u = be16toh(*u); \
		}                         \
	}

#define scap_reader_be32toh(r, u)         \
	{                                 \
		if(r->m_swap_endian)      \
		{                         \
			*u = be32toh(*u); \
		}                         \
	}

#define scap_reader_be64toh(r, u)         \
	{                                 \
		if(r->m_swap_endian)      \
		{                         \
			*u = be64toh(*u); \
		}                         \
	}

// inline void scap_reader_be_scap_machine_info_toh(scap_reader_t *r, scap_machine_info *i)
#define scap_reader_be_scap_machine_info_toh(r, i)                            \
	{                                                                     \
		if(r->m_swap_endian)                                          \
		{                                                             \
			i->num_cpus = be32toh(i->num_cpus);                   \
			i->memory_size_bytes = be64toh(i->memory_size_bytes); \
			i->max_pid = be64toh(i->max_pid);                     \
			i->reserved1 = be64toh(i->reserved1);                 \
			i->reserved2 = be64toh(i->reserved2);                 \
			i->reserved3 = be64toh(i->reserved3);                 \
			i->reserved4 = be64toh(i->reserved4);                 \
		}                                                             \
	}

// inline void scap_reader_be_scap_ifinfo_ipv4_toh(scap_reader_t *r, scap_ifinfo_ipv4 *i)
#define scap_reader_be_scap_ifinfo_ipv4_toh(r, i)             \
	{                                                     \
		if(r->m_swap_endian)                          \
		{                                             \
			i->type = be16toh(i->type);           \
			i->ifnamelen = be16toh(i->ifnamelen); \
			i->addr = be32toh(i->addr);           \
			i->netmask = be32toh(i->netmask);     \
			i->bcast = be32toh(i->bcast);         \
			i->linkspeed = be64toh(i->linkspeed); \
		}                                             \
	}

// inline void scap_reader_be_scap_ifinfo_ipv6_toh(scap_reader_t *r, scap_ifinfo_ipv6 *i)
#define scap_reader_be_scap_ifinfo_ipv6_toh(r, i)             \
	{                                                     \
		if(r->m_swap_endian)                          \
		{                                             \
			i->type = be16toh(i->type);           \
			i->ifnamelen = be16toh(i->ifnamelen); \
			i->linkspeed = be64toh(i->linkspeed); \
		}                                             \
	}

// NOTE: scap_evt == struct ppm_evt_hdr
// inline void scap_reader_be_scap_evt_toh(scap_reader_t *r, scap_evt *e)
#ifdef PPM_ENABLE_SENTINEL
#define scap_reader_be_scap_evt_toh(r, e)                               \
	{                                                               \
		if(r->m_swap_endian)                                    \
		{                                                       \
			h->sentinel_begin = be32toh(h->sentinel_begin); \
			e->ts = be64toh(e->ts);                         \
			e->tid = be64toh(e->tid);                       \
			e->len = be32toh(e->len);                       \
			e->type = be16toh(e->type);                     \
			e->nparams = be32toh(e->nparams);               \
		}                                                       \
	}
#else
#define scap_reader_be_scap_evt_toh(r, e)                 \
	{                                                 \
		if(r->m_swap_endian)                      \
		{                                         \
			e->ts = be64toh(e->ts);           \
			e->tid = be64toh(e->tid);         \
			e->len = be32toh(e->len);         \
			e->type = be16toh(e->type);       \
			e->nparams = be32toh(e->nparams); \
		}                                         \
	}
#endif
