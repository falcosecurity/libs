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

#include "strlcpy.h"

//
// Get the event info table
//
const struct ppm_event_info* scap_get_event_info_table()
{
	return g_event_info;
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

const struct ppm_event_info* scap_event_getinfo(const scap_evt* e)
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

void scap_event_set_param_length_regular(scap_evt *event, uint32_t n, uint16_t len)
{
	memcpy((char *)event + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * n, &len, sizeof(uint16_t));
}

void scap_event_set_param_length_large(scap_evt *event, uint32_t n, uint32_t len)
{
	memcpy((char *)event + sizeof(struct ppm_evt_hdr) + sizeof(uint32_t) * n, &len, sizeof(uint32_t));
}

static inline int32_t scap_buffer_can_fit(struct scap_sized_buffer buf, size_t len)
{
	return (buf.size >= len);
}

int32_t scap_event_encode_params(struct scap_sized_buffer event_buf, size_t *event_size, char *error, enum ppm_event_type event_type, uint32_t n, ...)
{
    va_list args;
    va_start(args, n);
    int32_t ret = scap_event_encode_params_v(event_buf, event_size, error, event_type, n, args);
    va_end(args);

	return ret;
}

int32_t scap_event_encode_params_v(const struct scap_sized_buffer event_buf, size_t *event_size, char *error, enum ppm_event_type event_type, uint32_t n, va_list args)
{
	scap_evt *event = NULL;

	const struct ppm_event_info *event_info = &g_event_info[event_type];

	// len_size is the size in bytes of an entry of the parameter length array
	size_t len_size = sizeof(uint16_t);
	if((event_info->flags & EF_LARGE_PAYLOAD) != 0)
	{
		len_size = sizeof(uint32_t);
	}

	n = event_info->nparams < n ? event_info->nparams : n;

	size_t len = sizeof(struct ppm_evt_hdr) + len_size * n;

	// every buffer write access needs to be guarded by a scap_buffer_can_fit call to check if it's large enough
	if (scap_buffer_can_fit(event_buf, len))
	{
		event = event_buf.buf;
		event->type = event_type;
		event->nparams = n;
		event->len = len;
	}

	for(int i = 0; i < n; i++)
	{
		const struct ppm_param_info *pi = &event_info->params[i];
		struct scap_const_sized_buffer param = {0};

        uint8_t u8_arg;
        uint16_t u16_arg;
        uint32_t u32_arg;
        uint64_t u64_arg;

		switch(pi->type)
		{
		case PT_INT8:
		case PT_UINT8:
		case PT_FLAGS8:
		case PT_SIGTYPE:
		case PT_L4PROTO:
		case PT_SOCKFAMILY:
		case PT_ENUMFLAGS8:
			u8_arg = (uint8_t) (va_arg(args, int) & 0xff);
			param.buf = &u8_arg;
			param.size = sizeof(uint8_t);
			break;

		case PT_INT16:
		case PT_UINT16:
		case PT_SYSCALLID:
		case PT_PORT:
		case PT_FLAGS16:
		case PT_ENUMFLAGS16:
			u16_arg = (uint16_t) (va_arg(args, int) & 0xffff);
			param.buf = &u16_arg;
			param.size = sizeof(uint16_t);
			break;

		case PT_INT32:
		case PT_UINT32:
		case PT_BOOL:
		case PT_IPV4ADDR:
		case PT_UID:
		case PT_GID:
		case PT_FLAGS32:
		case PT_SIGSET:
		case PT_MODE:
		case PT_ENUMFLAGS32:
            u32_arg = va_arg(args, uint32_t);
            param.buf = &u32_arg;
            param.size = sizeof(uint32_t);
			break;

		case PT_INT64:
		case PT_UINT64:
		case PT_ERRNO:
		case PT_FD:
		case PT_PID:
		case PT_RELTIME:
		case PT_ABSTIME:
		case PT_DOUBLE:
            u64_arg = va_arg(args, uint64_t);
            param.buf = &u64_arg;
            param.size = sizeof(uint64_t);
			break;

		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
            param.buf = va_arg(args, char*);
			if(param.buf == NULL)
			{
				param.size = 0;
			}
			else
			{
				param.size = strlen(param.buf) + 1;
			}
			break;

		case PT_BYTEBUF: /* A raw buffer of bytes not suitable for printing */
		case PT_SOCKTUPLE:  /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
		case PT_FDLIST:		    /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
		case PT_DYN:		    /* Type can vary depending on the context. Used for filter fields like evt.rawarg. */
		case PT_CHARBUFARRAY:	    /* Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only. */
		case PT_CHARBUF_PAIR_ARRAY: /* Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only. */
		case PT_IPV4NET:	    /* An IPv4 network. */
		case PT_IPV6ADDR:	    /* A 16 byte raw IPv6 address. */
		case PT_IPV6NET:	    /* An IPv6 network. */
		case PT_IPADDR:		    /* Either an IPv4 or IPv6 address. The length indicates which one it is. */
		case PT_IPNET:		    /* Either an IPv4 or IPv6 network. The length indicates which one it is. */
		case PT_SOCKADDR:
            param = va_arg(args, struct scap_const_sized_buffer);
			break;
			
		case PT_NONE:
        case PT_MAX:
			break; // Nothing to do 
		default: // Unsupported event
			snprintf(error, SCAP_LASTERR_SIZE, "event param %d (param type %d) is unsupported", i, pi->type);
			return SCAP_FAILURE;
		}

		uint16_t param_size_16;
		uint32_t param_size_32;

		switch(len_size)
		{
			case sizeof(uint16_t):
				param_size_16 = (uint16_t) (param.size & 0xffff);
				if (param_size_16 != param.size)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "could not fit event param %d size %zu for event with type %d in %zu bytes",
							i, param.size, event->type, len_size);
					return SCAP_FAILURE;
				}
				if (scap_buffer_can_fit(event_buf, len))
				{
					scap_event_set_param_length_regular(event, i, param_size_16);
				}
				break;
			case sizeof(uint32_t):
				param_size_32 = (uint32_t) (param.size & 0xffffffff);
				if (param_size_32 != param.size)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "could not fit event param %d size %zu for event with type %d in %zu bytes",
							i, param.size, event->type, len_size);
					return SCAP_FAILURE;
				}
				if (scap_buffer_can_fit(event_buf, len))
				{
					scap_event_set_param_length_large(event, i, param_size_32);
				}
				break;
			default:
				snprintf(error, SCAP_LASTERR_SIZE, "unexpected param %d length %zu for event with type %d",
						i, len_size, event->type);
				return SCAP_FAILURE;
		}

		if (scap_buffer_can_fit(event_buf, len + param.size) && param.size != 0)
		{
        	memcpy(((char*)event_buf.buf + len), param.buf, param.size);
		}
        len = len + param.size;
	}

#ifdef PPM_ENABLE_SENTINEL
	if (scap_buffer_can_fit(event_buf, len + sizeof(uint32_t)))
	{
		event->sentinel_begin = 0x01020304;
		memcpy(((char*)event_buf.buf + len), &event->sentinel_begin, sizeof(uint32_t));
	}
	len = len + sizeof(uint32_t);
#endif

	*event_size = len;

	// we were not able to write the event to the buffer
	if (!scap_buffer_can_fit(event_buf, len))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not encode event of size %zu into supplied buffer sized %zu.", len, event_buf.size);
		return SCAP_INPUT_TOO_SMALL;
	}

	event->len = len;

	return SCAP_SUCCESS;
}
