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

#include <libsinsp/sinsp_errno.h>

#ifndef _WIN32
#include <inttypes.h>
#include <sys/socket.h>
#include <algorithm>
#include <unistd.h>
#else
#define NOMINMAX
#define localtime_r(a, b) (localtime_s(b, a) == 0 ? b : NULL)
#endif

#include <limits>
#include <string>
#include <optional>
#include <functional>
#include <filesystem>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/strl.h>

#include <libscap/scap.h>

extern sinsp_evttables g_infotables;

#define SET_NUMERIC_FORMAT(resfmt, fmt, ostr, ustr, xstr) do {	\
	if(fmt == ppm_print_format::PF_OCT)                     \
	{                                                       \
		resfmt = (char*)"%#" ostr;                       \
	}                                                       \
	else if(fmt == ppm_print_format::PF_DEC)		\
	{                                                       \
		resfmt = (char*)"%" ustr;                       \
	}                                                       \
	else if(fmt == ppm_print_format::PF_10_PADDED_DEC)      \
	{                                                       \
		resfmt = (char*)"%09" ustr;                     \
	}                                                       \
	else if(fmt == ppm_print_format::PF_HEX)                \
	{                                                       \
		resfmt = (char*)"%" xstr;                       \
	}                                                       \
	else                                                    \
	{                                                       \
		resfmt = (char*)"%" ustr;                       \
	}                                                       \
} while(0)

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_evt::sinsp_evt() :
		m_inspector(NULL),
		m_pevt(NULL),
		m_poriginal_evt(NULL),
		m_pevt_storage(NULL),
		m_cpuid(0),
		m_evtnum(0),
		m_flags(EF_NONE),
		m_params_loaded(false),
		m_info(NULL),
		m_paramstr_storage(256),
		m_resolved_paramstr_storage(1024),
		m_tinfo(NULL),
		m_fdinfo(NULL),
		m_fdinfo_name_changed(false),
		m_iosize(0),
		m_errorcode(0),
		m_rawbuf_str_len(0),
		m_filtered_out(false),
		m_event_info_table(g_infotables.m_event_info)
{

}

sinsp_evt::sinsp_evt(sinsp *inspector) :
		m_inspector(inspector),
		m_pevt(NULL),
		m_poriginal_evt(NULL),
		m_pevt_storage(NULL),
		m_cpuid(0),
		m_evtnum(0),
		m_flags(EF_NONE),
		m_params_loaded(false),
		m_info(NULL),
		m_paramstr_storage(1024),
		m_resolved_paramstr_storage(1024),
		m_tinfo(NULL),
		m_fdinfo(NULL),
		m_fdinfo_name_changed(false),
		m_iosize(0),
		m_errorcode(0),
		m_rawbuf_str_len(0),
		m_filtered_out(false),
		m_event_info_table(g_infotables.m_event_info)
{
}

sinsp_evt::~sinsp_evt()
{
	if(m_pevt_storage)
	{
		delete[] m_pevt_storage;
	}
}

const char *sinsp_evt::get_name() const
{
	return m_info->name;
}

event_direction sinsp_evt::get_direction() const
{
	return (event_direction)(m_pevt->type & PPME_DIRECTION_FLAG);
}

int64_t sinsp_evt::get_tid() const
{
	return m_pevt->tid;
}

void sinsp_evt::set_iosize(uint32_t size)
{
	m_iosize = size;
}

uint32_t sinsp_evt::get_iosize() const
{
	return m_iosize;
}

sinsp_threadinfo* sinsp_evt::get_thread_info(bool query_os_if_not_found)
{
	if(NULL != m_tinfo)
	{
		return m_tinfo;
	}
	else if(m_tinfo_ref)
	{
		m_tinfo = m_tinfo_ref.get();

		return m_tinfo;
	}

	return m_inspector->get_thread_ref(m_pevt->tid, query_os_if_not_found, false).get();
}

int64_t sinsp_evt::get_fd_num() const
{
	if(m_fdinfo)
	{
		return m_tinfo->m_lastevent_fd;
	}
	else
	{
		return sinsp_evt::INVALID_FD_NUM;
	}
}


uint32_t sinsp_evt::get_num_params()
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	return (uint32_t)m_params.size();
}

const sinsp_evt_param *sinsp_evt::get_param(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	return &(m_params.at(id));
}

const sinsp_evt_param* sinsp_evt::get_param_by_name(const char* name)
{
	//
	// Make sure the params are actually loaded
	//
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	//
	// Locate the parameter given the name
	//
	uint32_t np = get_num_params();

	for(uint32_t j = 0; j < np; j++)
	{
		if(strcmp(name, get_param_name(j)) == 0)
		{
			return &(m_params[j]);
		}
	}

	return NULL;
}

const char *sinsp_evt::get_param_name(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < m_info->nparams);

	return m_info->params[id].name;
}

const ppm_param_info* sinsp_evt::get_param_info(uint32_t id)
{
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < m_info->nparams);

	return &(m_info->params[id]);
}

static uint32_t binary_buffer_to_hex_string(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k;
	uint32_t l = 0;
	uint32_t num_chunks;
	uint32_t row_len;
	char row[128];
	const char *ptr;
	bool truncated = false;

	for(j = 0; j < srclen; j += 8 * sizeof(uint16_t))
	{
		k = 0;
		k += snprintf(row + k, sizeof(row) - k, "\n\t0x%.4x:", j);

		ptr = &src[j];
		num_chunks = 0;
		while(num_chunks < 8 && ptr < src + srclen)
		{
			uint16_t chunk = htons(*(uint16_t*)ptr);

			int ret;
			if(ptr == src + srclen - 1)
			{
				ret = snprintf(row + k, sizeof(row) - k, " %.2x", *(((uint8_t*)&chunk) + 1));
			}
			else
			{
				ret = snprintf(row + k, sizeof(row) - k, " %.4x", chunk);
			}
			if (ret < 0 || (unsigned int)ret >= sizeof(row) - k)
			{
				dst[0] = 0;
				return 0;
			}

			k += ret;
			num_chunks++;
			ptr += sizeof(uint16_t);
		}

		if((fmt & sinsp_evt::PF_HEXASCII) || (fmt & sinsp_evt::PF_JSONHEXASCII))
		{
			// Fill the row with spaces to align it to other rows
			while(num_chunks < 8)
			{
				memset(row + k, ' ', 5);

				k += 5;
				num_chunks++;
			}

			row[k++] = ' ';
			row[k++] = ' ';

			for(ptr = &src[j];
				ptr < src + j + 8 * sizeof(uint16_t) && ptr < src + srclen;
				ptr++, k++)
			{
				if(isprint((int)(uint8_t)*ptr))
				{
					row[k] = *ptr;
				}
				else
				{
					row[k] = '.';
				}
			}
		}
		row[k] = 0;

		row_len = (uint32_t)strlen(row);
		if(l + row_len >= dstlen - 1)
		{
			truncated = true;
			break;
		}
		strlcpy(dst + l, row, dstlen - l);
		l += row_len;
	}

	dst[l++] = '\n';

	if(truncated)
	{
		return dstlen;
	}
	else
	{
		return l;
	}
}

static uint32_t binary_buffer_to_asciionly_string(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k = 0;

	if(fmt != sinsp_evt::PF_EOLS_COMPACT)
	{
		dst[k++] = '\n';
	}

	for(j = 0; j < srclen; j++)
	{
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1)
		{
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint((int)(uint8_t)src[j]))
		{
			// switch(src[j])
			// {
			// case '"':
			// case '\\':
			// 	dst[k++] = '\\';
			// 	break;
			// default:
			// 	break;
			// }

			dst[k] = src[j];
			k++;
		}
		else if(src[j] == '\r')
		{
			dst[k] = '\n';
			k++;
		}
		else if(src[j] == '\n')
		{
			if(j > 0 && src[j - 1] != '\r')
			{
				dst[k] = src[j];
				k++;
			}
		}

	}

	return k;
}

static uint32_t binary_buffer_to_string_dots(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t j;
	uint32_t k = 0;

	for(j = 0; j < srclen; j++)
	{
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1)
		{
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint((int)(uint8_t)src[j]))
		{
			// switch(src[j])
			// {
			// case '"':
			// case '\\':
			// 	dst[k++] = '\\';
			// 	break;
			// default:
			// 	break;
			// }

			dst[k] = src[j];
		}
		else
		{
			dst[k] = '.';
		}

		k++;
	}

	return k;
}

static uint32_t binary_buffer_to_base64_string(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	//
	// base64 encoder, malloc-free version of:
	// http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
	//
	static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/'};
	static uint32_t mod_table[] = {0, 2, 1};

	uint32_t j,k, enc_dstlen;

	enc_dstlen = 4 * ((srclen + 2) / 3);
	//
	// Make sure there's enough space in the target buffer.
	//
	if(enc_dstlen >= dstlen - 1)
	{
		return dstlen;
	}

	for (j = 0, k = 0; j < srclen;) {

		uint32_t octet_a = j < srclen ? (unsigned char)src[j++] : 0;
		uint32_t octet_b = j < srclen ? (unsigned char)src[j++] : 0;
		uint32_t octet_c = j < srclen ? (unsigned char)src[j++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		dst[k++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (j = 0; j < mod_table[srclen % 3]; j++)
		dst[enc_dstlen - 1 - j] = '=';

	return enc_dstlen;
}

static uint32_t binary_buffer_to_json_string(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t k = 0;
	switch(fmt)
	{
		case sinsp_evt::PF_JSONHEX:
		case sinsp_evt::PF_JSONHEXASCII:
			k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
			break;
		case sinsp_evt::PF_JSONEOLS:
			k =  binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
			break;
		case sinsp_evt::PF_JSONBASE64:
			k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
			break;
		default:
			k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}
	return k;
}

static uint32_t binary_buffer_to_string(char *dst, const char *src, uint32_t dstlen, uint32_t srclen, sinsp_evt::param_fmt fmt)
{
	uint32_t k = 0;

	if(dstlen == 0)
	{
		ASSERT(false);
		return 0;
	}

	if(srclen == 0)
	{
		*dst = 0;
		return 0;
	}

	if(fmt & sinsp_evt::PF_HEX || fmt & sinsp_evt::PF_HEXASCII)
	{
		k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & sinsp_evt::PF_BASE64)
	{
		k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & sinsp_evt::PF_JSON  || fmt & sinsp_evt::PF_JSONHEX
			|| fmt & sinsp_evt::PF_JSONEOLS || fmt & sinsp_evt::PF_JSONHEXASCII
            || fmt & sinsp_evt::PF_JSONBASE64)
	{
		k = binary_buffer_to_json_string(dst, src, dstlen, srclen, fmt);
	}
	else if(fmt & (sinsp_evt::PF_EOLS | sinsp_evt::PF_EOLS_COMPACT))
	{
		k = binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
	}
	else
	{
		k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}

	dst[k] = 0;
	return k;
}

static uint32_t strcpy_sanitized(char *dest, const char *src, uint32_t dstsize)
{
	volatile char* tmp = (volatile char *)dest;
	uint32_t j = 0;
	g_invalidchar ic;

	while(j < dstsize)
	{
		if(!ic(*src))
		{
			*tmp = *src;
			tmp++;
			j++;
		}

		if(*src == 0)
		{
			*tmp = 0;
			return j + 1;
		}

		src++;
	}

	//
	// In case there wasn't enough space, null-terminate the destination
	//
	if(dstsize)
	{
		dest[dstsize - 1] = 0;
	}

	return dstsize;
}

int sinsp_evt::render_fd_json(Json::Value *ret, int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	sinsp_threadinfo* tinfo = get_thread_info();
	if(tinfo == NULL)
	{
		return 0;
	}

	if(fd >= 0)
	{
		sinsp_fdinfo *fdinfo = tinfo->get_fd(fd);
		if(fdinfo)
		{
			char tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				scap_l4_proto l4p = fdinfo->get_l4proto();

				switch(l4p)
				{
				case SCAP_L4_TCP:
					ipprotoch = 't';
					break;
				case SCAP_L4_UDP:
					ipprotoch = 'u';
					break;
				case SCAP_L4_ICMP:
					ipprotoch = 'i';
					break;
				case SCAP_L4_RAW:
					ipprotoch = 'r';
					break;
				default:
					break;
				}
			}

			char typestr[3] =
			{
				(fmt & PF_SIMPLE)?(char)0:tch,
				ipprotoch,
				0
			};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			std::string sanitized_str = fdinfo->m_name;

			sanitize_string(sanitized_str);

			(*ret)["typechar"] = typestr;
			(*ret)["name"] = sanitized_str;
		}
	}
	else if(fd == PPM_AT_FDCWD)
	{
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		(*ret)["name"] = "AT_FDCWD";
	}
	else
	{
		//
		// Resolve this as an errno
		//
		std::string errstr(sinsp_utils::errno_to_str((int32_t)fd));
		if(errstr != "")
		{
			(*ret)["error"] = errstr;
			return 0;
		}
	}

	return 1;
}

char* sinsp_evt::render_fd(int64_t fd, const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	//
	// Add the fd number
	//
	snprintf(&m_paramstr_storage[0],
		        m_paramstr_storage.size(),
		        "%" PRId64, fd);

	sinsp_threadinfo* tinfo = get_thread_info();
	if(tinfo == NULL)
	{
		//
		// no thread. Definitely can't resolve the fd, just return the number
		//
		return &m_paramstr_storage[0];
	}

	if(fd >= 0)
	{
		sinsp_fdinfo *fdinfo = tinfo->get_fd(fd);
		if(fdinfo)
		{
			char tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
				fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK ||
				fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				scap_l4_proto l4p = fdinfo->get_l4proto();

				switch(l4p)
				{
				case SCAP_L4_TCP:
					ipprotoch = 't';
					break;
				case SCAP_L4_UDP:
					ipprotoch = 'u';
					break;
				case SCAP_L4_ICMP:
					ipprotoch = 'i';
					break;
				case SCAP_L4_RAW:
					ipprotoch = 'r';
					break;
				default:
					break;
				}
			}

			char typestr[3] =
			{
				(fmt & PF_SIMPLE)?(char)0:tch,
				ipprotoch,
				0
			};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			std::string sanitized_str = fdinfo->m_name;

			sanitize_string(sanitized_str);

			//
			// Make sure the string will fit
			//
			if(sanitized_str.size() >= m_resolved_paramstr_storage.size())
			{
				m_resolved_paramstr_storage.resize(sanitized_str.size() + 1);
			}

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"<%s>%s", typestr, sanitized_str.c_str());
		}
	}
	else if(fd == PPM_AT_FDCWD)
	{
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		snprintf(&m_resolved_paramstr_storage[0],
				 m_resolved_paramstr_storage.size(),
				 "AT_FDCWD");
	}
	else
	{
		//
		// Resolve this as an errno
		//
		std::string errstr(sinsp_utils::errno_to_str((int32_t)fd));
		if(errstr != "")
		{
			snprintf(&m_resolved_paramstr_storage[0],
				        m_resolved_paramstr_storage.size(),
				        "%s", errstr.c_str());
		}
	}

	return &m_paramstr_storage[0];
}

std::string sinsp_evt::get_base_dir(uint32_t id, sinsp_threadinfo *tinfo)
{
	std::string cwd = tinfo->get_cwd();

	const ppm_param_info* param_info = &m_info->params[id];

	// If it's a regular FSPATH, just return the thread's CWD
	if (param_info->type != PT_FSRELPATH)
	{
		ASSERT(param_info->type == PT_FSPATH);
		return cwd;
	}

	uint64_t dirfd_id = (uint64_t)param_info->info;
	if (dirfd_id >= m_info->nparams)
	{
		ASSERT(dirfd_id < m_info->nparams);
		return cwd;
	}

	const ppm_param_info* dir_param_info = &(m_info->params[dirfd_id]);
	// Ensure the index points to an actual FD
	if (dir_param_info->type != PT_FD)
	{
		ASSERT(dir_param_info->type == PT_FD);
		return cwd;
	}

	const int64_t dirfd = get_param(dirfd_id)->as<int64_t>();

	// If the FD is special value PPM_AT_FDCWD, just use CWD
	if (dirfd == PPM_AT_FDCWD)
	{
		return cwd;
	}

	// If the previous param is a fd with a value other than AT_FDCWD,
	// get the path to that fd and use it in place of CWD
	std::string rel_path_base = tinfo->get_path_for_dir_fd(dirfd);
	if (rel_path_base.empty())
	{
		return rel_path_base;
	}
	sanitize_string(rel_path_base);
	rel_path_base.append("/");
	return rel_path_base;
}

const char* sinsp_evt::get_param_as_str(uint32_t id, OUT const char** resolved_str, sinsp_evt::param_fmt fmt)
{
	char* prfmt = NULL;
	const ppm_param_info* param_info = NULL;
	std::optional<sinsp_evt_param> dyn_param;
	std::string_view s;
	uint8_t sockfamily;
	uint32_t j = 0;

	//
	// Make sure the params are actually loaded
	//
	if((m_flags & sinsp_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)sinsp_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < get_num_params());

	//
	// Reset the resolved string
	//
	m_resolved_paramstr_storage[0] = 0;

	//
	// Get the parameter
	//
	const sinsp_evt_param *param = get_param(id);
	param_info = param->get_info();

	if(param->m_len == 0)
	{
		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "NULL");
		*resolved_str = &m_resolved_paramstr_storage[0];
		return &m_paramstr_storage[0];
	}

	//
	// Get the parameter information
	//
	if(param_info->type == PT_DYN && param_info->info != NULL)
	{
		uint8_t dyn_idx = 0;
		memcpy(&dyn_idx, param->m_val, sizeof(uint8_t));

		if(dyn_idx < param_info->ninfo) {
			auto dyn_params = (const ppm_param_info*)param_info->info;

			dyn_param = sinsp_evt_param(param->m_evt, param->m_idx,
				param->m_val + sizeof(uint8_t), param->m_len - sizeof(uint8_t));

			param = std::addressof(*dyn_param);
			param_info = &dyn_params[dyn_idx];
		}
	}

	ppm_print_format param_fmt = m_info->params[id].fmt;

	switch(param_info->type)
	{
	case PT_INT8:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, param->as<int8_t>());
		break;
	case PT_INT16:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, param->as<int16_t>());
		break;
	case PT_INT32:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, param->as<int32_t>());
		break;
	case PT_INT64:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0],
			m_paramstr_storage.size(),
			prfmt, param->as<int64_t>());
		break;
	case PT_FD:
		{
			int64_t fd = param->as<int64_t>();
			render_fd(fd, resolved_str, fmt);
			break;
		}
	case PT_PID:
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRId64, param->as<int64_t>());

			sinsp_threadinfo* atinfo = m_inspector->get_thread_ref(param->as<int64_t>(), false, true).get();
			if(atinfo != NULL)
			{
				std::string& tcomm = atinfo->m_comm;

				//
				// Make sure the string will fit
				//
				if(tcomm.size() >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(tcomm.size() + 1);
				}

				snprintf(&m_resolved_paramstr_storage[0],
						 m_resolved_paramstr_storage.size(),
						 "%s",
						 tcomm.c_str());
			}
		}
		break;
	case PT_UINT8:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, param->as<uint8_t>());
		break;
	case PT_UINT16:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, param->as<uint16_t>());
		break;
	case PT_UINT32:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, param->as<uint32_t>());
		break;
	case PT_ERRNO:
	{
		int64_t val = param->as<int64_t>();

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRId64, val);

		//
		// Resolve this as an errno
		//
		std::string errstr;

		if(val < 0)
		{
			errstr = sinsp_utils::errno_to_str((int32_t)val);

			if(errstr != "")
			{
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s", errstr.c_str());
			}
		}
	}
	break;
	case PT_UINT64:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         prfmt, param->as<int64_t>());

		break;
	case PT_CHARBUF:
		//
		// Make sure the string will fit
		//
		s = param->as<std::string_view>();
		if(s.length() + 1 > m_paramstr_storage.size())
		{
			m_paramstr_storage.resize(s.length() + 1);
		}

		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%s", s.data());
		break;
	case PT_FSPATH:
	case PT_FSRELPATH:
	{
		std::string_view path = param->as<std::string_view>();
		strcpy_sanitized(&m_paramstr_storage[0],
			path.data(),
			std::min(path.size() + 1, m_paramstr_storage.size()));

		sinsp_threadinfo* tinfo = get_thread_info();

		if(tinfo)
		{
			if(path != "<NA>")
			{
				std::string cwd = get_base_dir(id, tinfo);

				if(path.length() + cwd.length() + 1 >= m_resolved_paramstr_storage.size())
				{
					m_resolved_paramstr_storage.resize(path.length() + cwd.length() + 2, 0);
				}

				if(path.empty() || std::filesystem::path(path).is_absolute())
				{
					m_resolved_paramstr_storage[0] = 0;
				}
				else
				{
					std::string concatenated_path = sinsp_utils::concatenate_paths(cwd, path);
					strcpy_sanitized(&m_resolved_paramstr_storage[0], concatenated_path.data(), std::min(concatenated_path.size() + 1, m_resolved_paramstr_storage.size()));
				}
			}
		}
		else
		{
			*resolved_str = &m_paramstr_storage[0];
		}
	}
	break;
	case PT_BYTEBUF:
	{
		while(true)
		{
			uint32_t blen = binary_buffer_to_string(&m_paramstr_storage[0],
				param->m_val,
				(uint32_t)m_paramstr_storage.size() - 1,
				param->m_len,
				fmt);

			if(blen >= m_paramstr_storage.size() - 1)
			{
				//
				// The buffer didn't fit, expand it and try again
				//
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			ASSERT(m_inspector != NULL);
			if(m_inspector->m_max_evt_output_len != 0 &&
				blen > m_inspector->m_max_evt_output_len &&
				fmt == PF_NORMAL)
			{
				uint32_t real_len = std::min(blen, m_inspector->m_max_evt_output_len);

				m_rawbuf_str_len = real_len;
				if(real_len > 3)
				{
					m_paramstr_storage[real_len - 3] = '.';
					m_paramstr_storage[real_len - 2] = '.';
					m_paramstr_storage[real_len - 1] = '.';
				}

				m_paramstr_storage[real_len] = 0;
			}
			else
			{
				m_rawbuf_str_len = blen;
			}
			break;
		}
	}
	break;
	case PT_SOCKADDR:
		sockfamily = param->m_val[0];
		if(sockfamily == PPM_AF_UNIX)
		{
			ASSERT(param->m_len > 1);

			//
			// Sanitize the file string.
			//
            std::string sanitized_str = param->m_val + 1;
			sanitize_string(sanitized_str);

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%s",
				sanitized_str.c_str());
		}
		else if(sockfamily == PPM_AF_INET)
		{
			if(param->m_len == 1 + 4 + 2)
			{
				ipv4serverinfo addr;
				memcpy(&addr.m_ip, param->m_val + 1, sizeof(addr.m_ip));
				memcpy(&addr.m_port, param->m_val + 5, sizeof(addr.m_port));
				addr.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr = ipv4serveraddr_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else if(sockfamily == PPM_AF_INET6)
		{
			if(param->m_len == 1 + 16 + 2)
			{
				ipv6serverinfo addr;
				memcpy((uint8_t *) addr.m_ip.m_b, (uint8_t *) param->m_val + 1, sizeof(addr.m_ip.m_b));
				memcpy(&addr.m_port, param->m_val + 17, sizeof(addr.m_port));
				addr.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr = ipv6serveraddr_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv6");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", sockfamily);
		}
		break;
	case PT_SOCKTUPLE:
		sockfamily = param->m_val[0];
		if(sockfamily == PPM_AF_INET)
		{
			if(param->m_len == 1 + 4 + 2 + 4 + 2)
			{
				ipv4tuple addr;
				memcpy(&addr.m_fields.m_sip, param->m_val + 1, sizeof(uint32_t));
				memcpy(&addr.m_fields.m_sport, param->m_val + 5, sizeof(uint16_t));
				memcpy(&addr.m_fields.m_dip, param->m_val + 7, sizeof(uint32_t));
				memcpy(&addr.m_fields.m_dport, param->m_val + 11, sizeof(uint16_t));
				addr.m_fields.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr = ipv4tuple_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);
				snprintf(&m_paramstr_storage[0],
					   	 m_paramstr_storage.size(),
					   	 "%s",
					   	 straddr.c_str());
			}
			else
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
				         m_paramstr_storage.size(),
				         "INVALID IPv4");
			}
		}
		else if(sockfamily == PPM_AF_INET6)
		{
			if(param->m_len == 1 + 16 + 2 + 16 + 2)
			{
				uint8_t* sip6 = (uint8_t*)param->m_val + 1;
				uint8_t* dip6 = (uint8_t*)param->m_val + 19;
				uint8_t* sip = (uint8_t*)param->m_val + 13;
				uint8_t* dip = (uint8_t*)param->m_val + 31;

				if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
				{
					ipv4tuple addr;
					memcpy(&addr.m_fields.m_sip, sip, sizeof(uint32_t));
					memcpy(&addr.m_fields.m_sport, param->m_val + 17, sizeof(uint16_t));
					memcpy(&addr.m_fields.m_dip, dip, sizeof(uint32_t));
					memcpy(&addr.m_fields.m_dport, param->m_val + 35, sizeof(uint16_t));
					addr.m_fields.m_l4proto = (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
					std::string straddr = ipv4tuple_to_string(&addr, m_inspector->m_hostname_and_port_resolution_enabled);

					snprintf(&m_paramstr_storage[0],
							 m_paramstr_storage.size(),
							 "%s",
							 straddr.c_str());
					break;
				}
				else
				{
					char srcstr[INET6_ADDRSTRLEN];
					char dststr[INET6_ADDRSTRLEN];
					if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
						inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr)))
					{
						uint16_t srcport, dstport;
						memcpy(&srcport, param->m_val + 17, sizeof(srcport));
						memcpy(&dstport, param->m_val + 35, sizeof(dstport));
						snprintf(&m_paramstr_storage[0],
								 m_paramstr_storage.size(),
								 "%s:%s->%s:%s",
								 srcstr,
								 port_to_string(srcport, (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN, m_inspector->m_hostname_and_port_resolution_enabled).c_str(),
								 dststr,
								 port_to_string(dstport, (m_fdinfo != NULL) ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN, m_inspector->m_hostname_and_port_resolution_enabled).c_str());
						break;
					}
				}
			}

			ASSERT(false);
			snprintf(&m_paramstr_storage[0],
				        m_paramstr_storage.size(),
				        "INVALID IPv6");
		}
		else if(sockfamily == PPM_AF_UNIX)
		{
			ASSERT(param->m_len > 17);

			//
			// Sanitize the file string.
			//
			std::string sanitized_str = param->m_val + 17;
			sanitize_string(sanitized_str);

			uint64_t src, dst;
			memcpy(&src, param->m_val + 1, sizeof(uint64_t));
			memcpy(&dst, param->m_val + 9, sizeof(uint64_t));

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIx64 "->%" PRIx64 " %s",
				src,
				dst,
				sanitized_str.c_str());
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "family %d", sockfamily);
		}
		break;
	case PT_FDLIST:
		{
			sinsp_threadinfo* tinfo = get_thread_info();
			if(!tinfo)
			{
				break;
			}

			uint16_t nfds = 0;
			memcpy(&nfds, param->m_val, sizeof(nfds));
			uint32_t pos = 2;
			uint32_t spos = 0;

			m_paramstr_storage[0] = 0;

			for(j = 0; j < nfds; j++)
			{
				char tch;
				int64_t fd = 0;
				memcpy(&fd, param->m_val + pos, sizeof(uint64_t));

				sinsp_fdinfo *fdinfo = tinfo->get_fd(fd);
				if(fdinfo)
				{
					tch = fdinfo->get_typechar();
				}
				else
				{
					tch = '?';
				}

				int16_t p8;
				memcpy(&p8, param->m_val + pos + 8, sizeof(int16_t));

				int r = snprintf(&m_paramstr_storage[0] + spos,
						m_paramstr_storage.size() - spos,
						"%" PRIu64 ":%c%x%c",
						fd,
						tch,
						(uint32_t) p8,
						(j < (uint32_t)(nfds - 1)) ? ' ' : '\0');

				if(r < 0 || spos + r >= m_paramstr_storage.size() - 1)
				{
					m_paramstr_storage[m_paramstr_storage.size() - 1] = 0;
					break;
				}

				spos += r;
				pos += 10;
			}
		}
		break;
	case PT_SYSCALLID:
		{
			uint16_t ppm_sc = param->as<uint16_t>();
			if(ppm_sc >= PPM_SC_MAX)
			{
				ASSERT(false);
				snprintf(&m_paramstr_storage[0],
						 m_paramstr_storage.size(),
						 "<unknown syscall>");
				break;
			}

			snprintf(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%" PRIu16,
				ppm_sc);

			snprintf(&m_resolved_paramstr_storage[0],
				m_resolved_paramstr_storage.size(),
				"%s",
				scap_get_ppm_sc_name((ppm_sc_code)ppm_sc));
		}
		break;
	case PT_SIGTYPE:
		{
			const char* sigstr;

			uint8_t val = param->as<uint8_t>();

			sigstr = sinsp_utils::signal_to_str(val);

			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu8, val);

			if(sigstr)
			{
				snprintf(&m_resolved_paramstr_storage[0],
							m_resolved_paramstr_storage.size(),
							"%s", sigstr);
			}
		}
		break;
	case PT_RELTIME:
		{
			std::string sigstr;

			uint64_t val = param->as<uint64_t>();

			if(val == (uint64_t)(-1))
			{
				snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "none");
				m_resolved_paramstr_storage[0] = '\0';
			}
			else
			{
				snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%" PRIu64, val);

				snprintf(&m_resolved_paramstr_storage[0],
					 m_resolved_paramstr_storage.size(),
					 "%lgs",
					 ((double)val) / 1000000000);
			}
		}
		break;
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
	case PT_ENUMFLAGS8:
	case PT_ENUMFLAGS16:
	case PT_ENUMFLAGS32:
		{
			uint32_t val = 0;
			switch(param_info->type)
			{
			case PT_FLAGS8:
			case PT_ENUMFLAGS8:
				val = param->as<uint8_t>();
				break;
			case PT_FLAGS16:
			case PT_ENUMFLAGS16:
				val = param->as<uint16_t>();
				break;
			case PT_FLAGS32:
			case PT_ENUMFLAGS32:
				val = param->as<uint32_t>();
				break;
			default:
				ASSERT(false);
			}
			snprintf(&m_paramstr_storage[0],
				     m_paramstr_storage.size(),
				     "%" PRIu32, val);

			auto flags = (const ppm_name_value*)m_info->params[id].info;
			const bool exact_match = param_info->type == PT_ENUMFLAGS8 || param_info->type == PT_ENUMFLAGS16 || param_info->type == PT_ENUMFLAGS32;
			const char *separator = "";
			uint32_t initial_val = val;
			uint32_t j = 0;

			while(flags != NULL && flags->name != NULL)
			{
				bool match = false;
				if (exact_match)
				{
					match = flags->value == initial_val;
				}
				else
				{
					// If flag is 0, then initial_val needs to be 0 for the flag to be resolved
					if ((flags->value == 0 && initial_val == 0) ||
					   (flags->value != 0 && (val & flags->value) == flags->value && val != 0))
					{
						match = true;
						// We remove current flags value to avoid duplicate flags e.g. PPM_O_RDWR, PPM_O_RDONLY, PPM_O_WRONLY
						val &= ~flags->value;
					}
				}
				if (match)
				{
					if(m_resolved_paramstr_storage.size() < j + strlen(separator) + strlen(flags->name))
					{
						m_resolved_paramstr_storage.resize(m_resolved_paramstr_storage.size() * 2);
					}

					j += snprintf(&m_resolved_paramstr_storage[j],
						      m_resolved_paramstr_storage.size(),
						      "%s%s",
						      separator,
						      flags->name);
					separator = "|";
					if (!exact_match)
					{
						if (flags->value == initial_val)
						{
							// if we reached initial val, we have finished.
							// NOTE: for enum flags, we might have multiple flags matching same enum value
							// see socket_families (eg: AF_LOCAL, AF_UNIX). Don't break.
							break;
						}
					}
				}

				flags++;
			}

			break;
		}
	case PT_MODE:
		{
			uint32_t val = param->as<uint32_t>();
			SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);
			snprintf(&m_paramstr_storage[0],
					m_paramstr_storage.size(),
					prfmt, val);

			auto mode = (const ppm_name_value*)m_info->params[id].info;
			const char *separator = "";
			uint32_t initial_val = val;
			uint32_t j = 0;

			while(mode != NULL && mode->name != NULL && mode->value != initial_val)
			{
				// If mode is 0, then initial_val needs to be 0 for the mode to be resolved
				if((mode->value == 0 && initial_val == 0) ||
				   (mode->value != 0 && (val & mode->value) == mode->value && val != 0))
				{
					size_t params_len = j + strlen(separator) + strlen(mode->name);
					if(m_resolved_paramstr_storage.size() < params_len)
					{
						m_resolved_paramstr_storage.resize(params_len + 1);
					}

					j += snprintf(&m_resolved_paramstr_storage[j],
								m_resolved_paramstr_storage.size(),
								"%s%s",
								separator,
								mode->name);

					separator = "|";
					// We remove current mode value to avoid duplicates
					val &= ~mode->value;
				}

				mode++;
			}

			if(mode != NULL && mode->name != NULL)
			{
				j += snprintf(&m_resolved_paramstr_storage[j],
							  m_resolved_paramstr_storage.size(),
							  "%s%s",
							  separator,
							  mode->name);
			}

			break;
		}
	case PT_ABSTIME:
		{
			uint64_t val = param->as<uint64_t>();
			time_t sec = val / 1000000000ULL;
			unsigned long nsec = val % 1000000000ULL;
			struct tm tm;
			localtime_r(&sec, &tm);
			strftime(&m_paramstr_storage[0],
				m_paramstr_storage.size(),
				"%Y-%m-%d %H:%M:%S.XXXXXXXXX %z", &tm);
			snprintf(&m_paramstr_storage[20], 10, "%09ld", nsec);
			break;
		}
	case PT_DYN:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "INVALID DYNAMIC PARAMETER");
		break;
	case PT_UID:
	{
		uint32_t val = param->as<uint32_t>();
		if (val < std::numeric_limits<uint32_t>::max())
		{
			// Note: we want to resolve user given the uid
			// from the event.
			// Eg: for setuid() the requested uid is not
			// the threadinfo one yet;
			// therefore we cannot directly use tinfo->m_user here.
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%d", val);
			sinsp_threadinfo* tinfo = get_thread_info();
			scap_userinfo *user_info = NULL;
			if (tinfo)
			{
				user_info = m_inspector->m_usergroup_manager.get_user(tinfo->m_container_id, val);
			}
			if (user_info != NULL)
			{
				strcpy_sanitized(&m_resolved_paramstr_storage[0], user_info->name,
								(uint32_t)m_resolved_paramstr_storage.size());
			}
			else
			{
				snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"<NA>");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "-1");
			snprintf(&m_resolved_paramstr_storage[0],
					m_resolved_paramstr_storage.size(),
					"<NONE>");
		}
		break;
	}
	case PT_GID:
	{
		uint32_t val = param->as<uint32_t>();
		if (val < std::numeric_limits<uint32_t>::max())
		{
			// Note: we want to resolve group given the gid
			// from the event.
			// Eg: for setgid() the requested gid is not
			// the threadinfo one yet;
			// therefore we cannot directly use tinfo->m_group here.
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "%d", val);
			sinsp_threadinfo* tinfo = get_thread_info();
			scap_groupinfo *group_info = NULL;
			if (tinfo)
			{
				group_info = m_inspector->m_usergroup_manager.get_group(tinfo->m_container_id, val);
			}
			if (group_info != NULL)
			{
				strcpy_sanitized(&m_resolved_paramstr_storage[0], group_info->name,
								(uint32_t)m_resolved_paramstr_storage.size());
			}
			else
			{
				snprintf(&m_resolved_paramstr_storage[0],
						m_resolved_paramstr_storage.size(),
						"<NA>");
			}
		}
		else
		{
			snprintf(&m_paramstr_storage[0],
					 m_paramstr_storage.size(),
					 "-1");
			snprintf(&m_resolved_paramstr_storage[0],
					m_resolved_paramstr_storage.size(),
					"<NONE>");
		}
		break;
	}
	case PT_CHARBUFARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		std::vector<char*>* strvect = (std::vector<char*>*)*(uint64_t *)param->m_val;

		m_paramstr_storage[0] = 0;

		while(true)
		{
			std::vector<char*>::iterator it;
			std::vector<char*>::iterator itbeg;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it = itbeg = strvect->begin(); it != strvect->end(); ++it)
			{
				char* src = *it;

				if(it != itbeg)
				{
					if(dst < dstend - 1)
					{
						*dst++ = '.';
					}
				}

				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}
	}
	break;
	case PT_CHARBUF_PAIR_ARRAY:
	{
		ASSERT(param->m_len == sizeof(uint64_t));
		std::pair<std::vector<char*>*, std::vector<char*>*>* pairs =
			(std::pair<std::vector<char*>*, std::vector<char*>*>*)*(uint64_t *)param->m_val;

		m_paramstr_storage[0] = 0;

		if(pairs->first->size() != pairs->second->size())
		{
			ASSERT(false);
			break;
		}

		while(true)
		{
			std::vector<char*>::iterator it1;
			std::vector<char*>::iterator itbeg1;
			std::vector<char*>::iterator it2;
			std::vector<char*>::iterator itbeg2;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char* dst = &m_paramstr_storage[0];
			char* dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it1 = itbeg1 = pairs->first->begin(), it2 = itbeg2 = pairs->second->begin();
			it1 != pairs->first->end();
				++it1, ++it2)
			{
				char* src = *it1;

				if(it1 != itbeg1)
				{
					if(dst < dstend - 1)
					{
						*dst++ = ',';
					}
				}

				//
				// Copy the first string
				//
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst < dstend - 1)
				{
					*dst++ = ':';
				}

				//
				// Copy the second string
				//
				src = *it2;
				while(*src != 0 && dst < dstend)
				{
					*dst++ = *src++;
				}

				if(dst == dstend)
				{
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize)
			{
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}

		break;
	}
	case PT_SIGSET:
	{
		uint32_t val = param->as<uint32_t>();

		m_resolved_paramstr_storage[0] = '\0';
		m_paramstr_storage[0]          = '\0';

		char* storage = &m_paramstr_storage[0];
		int remaining = (int)m_paramstr_storage.size();
		bool first = true;

		for(int sig = 0; sig < 32; sig++)
		{
			if(val & (1U << sig) )
			{
				const char* sigstr = sinsp_utils::signal_to_str(sig+1);
				if(sigstr)
				{
					int printed = snprintf(storage, remaining,
							       "%s%s",
							       !first ? " " : "",
							       sigstr);
					if(printed >= remaining)
					{
						storage[remaining-1] = '\0';
						break;
					}

					first	   = false;
					storage	  += printed;
					remaining -= printed;
				}
			}
		}
		break;
	}
	default:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "(n.a.)");
		break;
	}

	*resolved_str = &m_resolved_paramstr_storage[0];

	return &m_paramstr_storage[0];
}

std::string sinsp_evt::get_param_value_str(const std::string &name, bool resolved)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(name == get_param_name(i))
		{
			return get_param_value_str(i, resolved);
		}
	}

	return std::string("");
}

std::string sinsp_evt::get_param_value_str(const char *name, bool resolved)
{
	// TODO fix this !!
	std::string s_name = std::string(name);
	return get_param_value_str(s_name, resolved);
}

std::string sinsp_evt::get_param_value_str(uint32_t i, bool resolved)
{
	const char *param_value_str;
	const char *val_str;
	val_str = get_param_as_str(i, &param_value_str);

	if(resolved)
	{
		return std::string((*param_value_str == '\0')? val_str : param_value_str);
	}
	else
	{
		return std::string(val_str);
	}
}

const char* sinsp_evt::get_param_value_str(const char* name, OUT const char** resolved_str, param_fmt fmt)
{
	for(uint32_t i = 0; i < get_num_params(); i++)
	{
		if(strcmp(name, get_param_name(i)) == 0)
		{
			return get_param_as_str(i, resolved_str, fmt);
		}
	}

	*resolved_str = NULL;
	return NULL;
}

void sinsp_evt::get_category(OUT sinsp_evt::category* cat) const
{
	/* We always search the category inside the event table */
	cat->m_category = get_category();

	//
	// For EC_IO and EC_WAIT events, we dig into the fd state to get the category
	// and fdtype
	//
	if(cat->m_category & EC_IO_BASE)
	{
		if(!m_fdinfo)
		{
			//
			// The fd info is not present, likely because we missed its creation.
			//
			cat->m_subcategory = SC_UNKNOWN;
			return;
		}
		else
		{
			switch(m_fdinfo->m_type)
			{
				case SCAP_FD_FILE:
				case SCAP_FD_FILE_V2:
				case SCAP_FD_DIRECTORY:
					cat->m_subcategory = SC_FILE;
					break;
				case SCAP_FD_IPV4_SOCK:
				case SCAP_FD_IPV6_SOCK:
					cat->m_subcategory = SC_NET;
					break;
				case SCAP_FD_IPV4_SERVSOCK:
				case SCAP_FD_IPV6_SERVSOCK:
					cat->m_subcategory = SC_NET;
					break;
				case SCAP_FD_FIFO:
				case SCAP_FD_UNIX_SOCK:
				case SCAP_FD_EVENT:
				case SCAP_FD_SIGNALFD:
				case SCAP_FD_INOTIFY:
				case SCAP_FD_USERFAULTFD:
					cat->m_subcategory = SC_IPC;
					break;
				case SCAP_FD_UNSUPPORTED:
				case SCAP_FD_EVENTPOLL:
				case SCAP_FD_TIMERFD:
				case SCAP_FD_BPF:
				case SCAP_FD_IOURING:
				case SCAP_FD_NETLINK:
				case SCAP_FD_MEMFD:
				case SCAP_FD_PIDFD:
					cat->m_subcategory = SC_OTHER;
					break;
				case SCAP_FD_UNKNOWN:
					cat->m_subcategory = SC_OTHER;
					break;
				default:
					cat->m_subcategory = SC_UNKNOWN;
					break;
			}
		}
	}
	else
	{
		cat->m_subcategory = sinsp_evt::SC_NONE;
	}
}

bool sinsp_evt::is_filtered_out() const
{
	return m_filtered_out;
}

scap_dump_flags sinsp_evt::get_dump_flags(OUT bool* should_drop) const
{
	uint32_t dflags = SCAP_DF_NONE;
	*should_drop = false;

	if(m_filtered_out)
	{
		if(m_inspector->m_isfatfile_enabled)
		{
			ppm_event_flags eflags = get_info_flags();

			if(eflags & EF_MODIFIES_STATE)
			{
				dflags = SCAP_DF_STATE_ONLY;
			}
			else
			{
				*should_drop = true;
			}
		}
		else
		{
			*should_drop = true;
		}

		if(*should_drop)
		{
			ppm_event_category ecat = get_category();
			if(ecat & EC_INTERNAL)
			{
				*should_drop = false;
			}
		}
	}

	if(get_info_flags() & EF_LARGE_PAYLOAD)
	{
		dflags |= SCAP_DF_LARGE;
	}

	return (scap_dump_flags)dflags;
}

bool sinsp_evt::is_syscall_error() const
{
	return (m_errorcode != 0) &&
	       (m_errorcode != SE_EINPROGRESS) &&
	       (m_errorcode != SE_EAGAIN) &&
	       (m_errorcode != SE_ETIMEDOUT);
}

bool sinsp_evt::is_file_open_error() const
{
	return (m_fdinfo == nullptr) &&
	       ((m_pevt->type == PPME_SYSCALL_OPEN_X) ||
		(m_pevt->type == PPME_SYSCALL_CREAT_X) ||
		(m_pevt->type == PPME_SYSCALL_OPENAT_X) ||
		(m_pevt->type == PPME_SYSCALL_OPENAT_2_X) ||
		(m_pevt->type == PPME_SYSCALL_OPENAT2_X) ||
		(m_pevt->type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X));
}

bool sinsp_evt::is_file_error() const
{
	return is_file_open_error() ||
	       ((m_fdinfo != nullptr) &&
		((m_fdinfo->m_type == SCAP_FD_FILE) ||
		 (m_fdinfo->m_type == SCAP_FD_FILE_V2)));
}

bool sinsp_evt::is_network_error() const
{
	if(m_fdinfo != nullptr)
	{
		return (m_fdinfo->m_type == SCAP_FD_IPV4_SOCK) ||
		       (m_fdinfo->m_type == SCAP_FD_IPV6_SOCK);
	}
	else
	{
		return (m_pevt->type == PPME_SOCKET_ACCEPT_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT4_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT_5_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT4_5_X) ||
		       (m_pevt->type == PPME_SOCKET_ACCEPT4_6_X) ||
		       (m_pevt->type == PPME_SOCKET_CONNECT_X) ||
		       (m_pevt->type == PPME_SOCKET_BIND_X);
	}
}

uint64_t sinsp_evt::get_lastevent_ts() const
{
	return m_tinfo->m_lastevent_ts;
}

bool sinsp_evt::clone_event(sinsp_evt &dest, const sinsp_evt &src)
{
	dest.m_inspector = src.m_inspector;
	dest.m_poriginal_evt = nullptr;

	// tinfo
	if (src.m_tinfo_ref && src.m_tinfo && src.m_tinfo_ref.get() != src.m_tinfo)
	{
		// bad data
		return false;
	}

	if (src.m_tinfo_ref)
	{
		dest.m_tinfo_ref = src.m_tinfo_ref;
		dest.m_tinfo = dest.m_tinfo_ref.get();
	}
	else if (src.m_tinfo)
	{
		dest.m_tinfo_ref = dest.m_inspector->get_thread_ref(src.m_tinfo->m_tid, false, false);
		if (dest.m_tinfo_ref == nullptr)
		{
			// no tinfo
			return false;
		}
		dest.m_tinfo = dest.m_tinfo_ref.get();
	}
	else
	{
		dest.m_tinfo_ref = nullptr;
		dest.m_tinfo = nullptr;
	}

	if (src.m_pevt != nullptr)
	{
		dest.m_pevt_storage = new char[src.m_pevt->len];
		memcpy(dest.m_pevt_storage, src.m_pevt, src.m_pevt->len);
		dest.m_pevt = (scap_evt *) dest.m_pevt_storage;
	}
	else
	{
		dest.m_pevt_storage = nullptr;
		dest.m_pevt = nullptr;
	}

	// scalars
	dest.m_cpuid = src.m_cpuid;
	dest.m_evtnum = src.m_evtnum;
	dest.m_flags = src.m_flags;
	dest.m_params_loaded = src.m_params_loaded;

	dest.m_iosize = src.m_iosize;
	dest.m_errorcode = src.m_errorcode;
	dest.m_rawbuf_str_len = src.m_rawbuf_str_len;
	dest.m_filtered_out = src.m_filtered_out;

	// vectors
	dest.m_params = src.m_params;
	dest.m_paramstr_storage = src.m_paramstr_storage;
	dest.m_resolved_paramstr_storage = src.m_resolved_paramstr_storage;

	// global table
	dest.m_event_info_table = src.m_event_info_table;
	dest.m_info = src.m_info;

	// fd info
	dest.m_fdinfo = nullptr;
	dest.m_fdinfo_ref.reset();
	if (src.m_fdinfo != nullptr)
	{
		//m_fdinfo_ref is only used to keep a handle to this
		// copy of the fdinfo which was copied from the global fdinfo table
		dest.m_fdinfo_ref = src.m_fdinfo->clone();
		dest.m_fdinfo = dest.m_fdinfo_ref.get();
	}
	dest.m_fdinfo_name_changed = src.m_fdinfo_name_changed;

	return true;
}

void sinsp_evt::save_enter_event_params(sinsp_evt* enter_evt)
{
	static std::vector<const char *> path_param = {"path"};
	static std::vector<const char *> oldpath_newpath_param = {"oldpath", "newpath"};
	static std::vector<const char *> name_param = {"name"};

	std::vector<const char *> *pnames = NULL;
	switch(get_type())
	{
	case PPME_SYSCALL_MKDIR_X:
	case PPME_SYSCALL_RMDIR_X:
	case PPME_SYSCALL_UNLINK_X:
		pnames = &path_param;
		break;

	case PPME_SYSCALL_LINK_X:
	case PPME_SYSCALL_LINKAT_X:
		pnames = &oldpath_newpath_param;
		break;
	case PPME_SYSCALL_UNLINKAT_X:
	case PPME_SYSCALL_OPENAT_X:
		pnames = &name_param;
		break;
	};

	if(!pnames)
	{
		return;
	}

	for(const char *pname : (*pnames))
	{
		const sinsp_evt_param *param;

		param = enter_evt->get_param_by_name(pname);
		if(param)
		{
			std::string val {param->as<std::string_view>()};
			m_enter_path_param[pname] = val;
		}
	}
}

std::optional<std::reference_wrapper<const std::string>> sinsp_evt::get_enter_evt_param(const std::string& param) const
{
	auto it = m_enter_path_param.find(param);

	if(it != m_enter_path_param.end())
	{
		return it->second;
	}

	return std::nullopt;
}

void sinsp_evt_param::throw_invalid_len_error(size_t requested_length) const
{
	const ppm_param_info* parinfo = get_info();

	std::stringstream ss;
	ss << "could not parse param " << m_idx << " (" << parinfo->name << ") for event "
		<< m_evt->get_num() << " of type " << m_evt->get_type() << " (" << m_evt->get_name() << "): expected length "
		<< requested_length << ", found " << m_len;

	throw sinsp_exception(ss.str());
}

const ppm_param_info* sinsp_evt_param::get_info() const
{
	return &(m_evt->get_info()->params[m_idx]);
}
