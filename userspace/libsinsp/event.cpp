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
#include <sys/socket.h>
#include <algorithm>
#include <unistd.h>
#else
#define localtime_r(a, b) (localtime_s(b, a) == 0 ? b : nullptr)
#endif

#include <cinttypes>
#include <limits>
#include <string>
#include <optional>
#include <functional>
#include <filesystem>

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/user.h>
#include <libscap/strl.h>

#include <libscap/scap.h>
#include <libsinsp/utils.h>

extern sinsp_evttables g_infotables;

#define SET_NUMERIC_FORMAT(resfmt, fmt, ostr, ustr, xstr)      \
	do {                                                       \
		if(fmt == ppm_print_format::PF_OCT) {                  \
			resfmt = (char *)"%#" ostr;                        \
		} else if(fmt == ppm_print_format::PF_DEC) {           \
			resfmt = (char *)"%" ustr;                         \
		} else if(fmt == ppm_print_format::PF_10_PADDED_DEC) { \
			resfmt = (char *)"%09" ustr;                       \
		} else if(fmt == ppm_print_format::PF_HEX) {           \
			resfmt = (char *)"%" xstr;                         \
		} else {                                               \
			resfmt = (char *)"%" ustr;                         \
		}                                                      \
	} while(0)

///////////////////////////////////////////////////////////////////////////////
// sinsp_evt implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_evt::sinsp_evt():
        m_inspector(nullptr),
        m_pevt(nullptr),
        m_pevt_storage(nullptr),
        m_cpuid(0),
        m_evtnum(0),
        m_flags(EF_NONE),
        m_dump_flags(0),
        m_info(nullptr),
        m_paramstr_storage(1024),
        m_resolved_paramstr_storage(1024),
        m_tinfo(nullptr),
        m_fdinfo(nullptr),
        m_fdinfo_name_changed(false),
        m_iosize(0),
        m_errorcode(0),
        m_rawbuf_str_len(0),
        m_filtered_out(false),
        m_event_info_table(g_infotables.m_event_info),
        m_source_idx(sinsp_no_event_source_idx),
        m_source_name(nullptr) {}

sinsp_evt::sinsp_evt(sinsp *inspector): sinsp_evt() {
	m_inspector = inspector;
}

sinsp_evt::~sinsp_evt() {
	if(m_pevt_storage) {
		delete[] m_pevt_storage;
	}
}

const char *sinsp_evt::get_name() const {
	return m_info->name;
}

event_direction sinsp_evt::get_direction() const {
	return static_cast<event_direction>(m_pevt->type & PPME_DIRECTION_FLAG);
}

int64_t sinsp_evt::get_tid() const {
	return m_pevt->tid;
}

void sinsp_evt::set_iosize(const uint32_t size) {
	m_iosize = size;
}

uint32_t sinsp_evt::get_iosize() const {
	return m_iosize;
}

sinsp_threadinfo *sinsp_evt::get_thread_info() {
	if(m_tinfo != nullptr) {
		return m_tinfo;
	}

	if(m_tinfo_ref) {
		m_tinfo = m_tinfo_ref.get();
		return m_tinfo;
	}

	return m_inspector->m_thread_manager->find_thread(m_pevt->tid, false).get();
}

int64_t sinsp_evt::get_fd_num() const {
	if(m_fdinfo) {
		return m_tinfo->m_lastevent_fd;
	} else {
		return sinsp_evt::INVALID_FD_NUM;
	}
}

uint32_t sinsp_evt::get_num_params() {
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
	}

	return static_cast<uint32_t>(m_params.size());
}

const sinsp_evt_param *sinsp_evt::get_param(const uint32_t id) {
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
	}

	return &m_params.at(id);
}

const sinsp_evt_param *sinsp_evt::get_param_by_name(const char *name) {
	//
	// Make sure the params are actually loaded
	//
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
	}

	//
	// Locate the parameter given the name
	//
	const uint32_t np = get_num_params();
	for(uint32_t j = 0; j < np; j++) {
		if(strcmp(name, get_param_name(j)) == 0) {
			return &m_params[j];
		}
	}

	return nullptr;
}

const char *sinsp_evt::get_param_name(const uint32_t id) {
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
	}

	ASSERT(id < m_info->nparams);

	return m_info->params[id].name;
}

const ppm_param_info *sinsp_evt::get_param_info(const uint32_t id) {
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
	}

	ASSERT(id < m_info->nparams);

	return &m_info->params[id];
}

static uint32_t binary_buffer_to_hex_string(char *dst,
                                            const char *src,
                                            const uint32_t dstlen,
                                            const uint32_t srclen,
                                            const sinsp_evt::param_fmt fmt) {
	uint32_t l = 0;
	char row[128];
	bool truncated = false;

	for(uint32_t j = 0; j < srclen; j += 8 * sizeof(uint16_t)) {
		uint32_t k = 0;
		k += snprintf(row + k, sizeof(row) - k, "\n\t0x%.4x:", j);

		const char *ptr = &src[j];
		uint32_t num_chunks = 0;
		while(num_chunks < 8 && ptr < src + srclen) {
			uint16_t chunk = htons(*reinterpret_cast<const uint16_t *>(ptr));

			int ret;
			if(ptr == src + srclen - 1) {
				ret = snprintf(row + k,
				               sizeof(row) - k,
				               " %.2x",
				               *(reinterpret_cast<const uint8_t *>(&chunk) + 1));
			} else {
				ret = snprintf(row + k, sizeof(row) - k, " %.4x", chunk);
			}
			if(ret < 0 || static_cast<unsigned int>(ret) >= sizeof(row) - k) {
				dst[0] = 0;
				return 0;
			}

			k += ret;
			num_chunks++;
			ptr += sizeof(uint16_t);
		}

		if((fmt & sinsp_evt::PF_HEXASCII) || (fmt & sinsp_evt::PF_JSONHEXASCII)) {
			// Fill the row with spaces to align it to other rows
			while(num_chunks < 8) {
				memset(row + k, ' ', 5);

				k += 5;
				num_chunks++;
			}

			row[k++] = ' ';
			row[k++] = ' ';

			for(ptr = &src[j]; ptr < src + j + 8 * sizeof(uint16_t) && ptr < src + srclen;
			    ptr++, k++) {
				if(isprint(static_cast<uint8_t>(*ptr))) {
					row[k] = *ptr;
				} else {
					row[k] = '.';
				}
			}
		}
		row[k] = 0;

		const uint32_t row_len = static_cast<uint32_t>(strlen(row));
		if(l + row_len >= dstlen - 1) {
			truncated = true;
			break;
		}
		strlcpy(dst + l, row, dstlen - l);
		l += row_len;
	}

	dst[l++] = '\n';

	if(truncated) {
		return dstlen;
	}
	return l;
}

static uint32_t binary_buffer_to_asciionly_string(char *dst,
                                                  const char *src,
                                                  const uint32_t dstlen,
                                                  const uint32_t srclen,
                                                  const sinsp_evt::param_fmt fmt) {
	uint32_t k = 0;

	if(fmt != sinsp_evt::PF_EOLS_COMPACT) {
		dst[k++] = '\n';
	}

	for(uint32_t j = 0; j < srclen; j++) {
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1) {
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint(static_cast<uint8_t>(src[j]))) {
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
		} else if(src[j] == '\r') {
			dst[k] = '\n';
			k++;
		} else if(src[j] == '\n') {
			if(j > 0 && src[j - 1] != '\r') {
				dst[k] = src[j];
				k++;
			}
		}
	}

	return k;
}

static uint32_t binary_buffer_to_string_dots(char *dst,
                                             const char *src,
                                             const uint32_t dstlen,
                                             const uint32_t srclen,
                                             sinsp_evt::param_fmt /*fmt*/) {
	uint32_t k = 0;

	for(uint32_t j = 0; j < srclen; j++) {
		//
		// Make sure there's enough space in the target buffer.
		// Note that we reserve two bytes, because some characters are expanded
		// when copied.
		//
		if(k >= dstlen - 1) {
			dst[k - 1] = 0;
			return dstlen;
		}

		if(isprint(static_cast<uint8_t>(src[j]))) {
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
		} else {
			dst[k] = '.';
		}

		k++;
	}

	return k;
}

static uint32_t binary_buffer_to_base64_string(char *dst,
                                               const char *src,
                                               const uint32_t dstlen,
                                               const uint32_t srclen,
                                               sinsp_evt::param_fmt /*fmt*/) {
	//
	// base64 encoder, malloc-free version of:
	// http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
	//
	static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	                                'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	                                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	                                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	                                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
	static uint32_t mod_table[] = {0, 2, 1};

	uint32_t j, k;

	const uint32_t enc_dstlen = 4 * ((srclen + 2) / 3);
	//
	// Make sure there's enough space in the target buffer.
	//
	if(enc_dstlen >= dstlen - 1) {
		return dstlen;
	}

	for(j = 0, k = 0; j < srclen;) {
		const uint32_t octet_a = j < srclen ? static_cast<unsigned char>(src[j++]) : 0;
		const uint32_t octet_b = j < srclen ? static_cast<unsigned char>(src[j++]) : 0;
		const uint32_t octet_c = j < srclen ? static_cast<unsigned char>(src[j++]) : 0;

		const uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		dst[k++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		dst[k++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for(j = 0; j < mod_table[srclen % 3]; j++)
		dst[enc_dstlen - 1 - j] = '=';

	return enc_dstlen;
}

static uint32_t binary_buffer_to_json_string(char *dst,
                                             const char *src,
                                             uint32_t dstlen,
                                             uint32_t srclen,
                                             sinsp_evt::param_fmt fmt) {
	uint32_t k = 0;
	switch(fmt) {
	case sinsp_evt::PF_JSONHEX:
	case sinsp_evt::PF_JSONHEXASCII:
		k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
		break;
	case sinsp_evt::PF_JSONEOLS:
		k = binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
		break;
	case sinsp_evt::PF_JSONBASE64:
		k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
		break;
	default:
		k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}
	return k;
}

uint32_t binary_buffer_to_string(char *dst,
                                 const char *src,
                                 const uint32_t dstlen,
                                 const uint32_t srclen,
                                 const sinsp_evt::param_fmt fmt) {
	uint32_t k = 0;

	if(dstlen == 0) {
		ASSERT(false);
		return 0;
	}

	if(srclen == 0) {
		*dst = 0;
		return 0;
	}

	if(fmt & sinsp_evt::PF_HEX || fmt & sinsp_evt::PF_HEXASCII) {
		k = binary_buffer_to_hex_string(dst, src, dstlen, srclen, fmt);
	} else if(fmt & sinsp_evt::PF_BASE64) {
		k = binary_buffer_to_base64_string(dst, src, dstlen, srclen, fmt);
	} else if(fmt & sinsp_evt::PF_JSON || fmt & sinsp_evt::PF_JSONHEX ||
	          fmt & sinsp_evt::PF_JSONEOLS || fmt & sinsp_evt::PF_JSONHEXASCII ||
	          fmt & sinsp_evt::PF_JSONBASE64) {
		k = binary_buffer_to_json_string(dst, src, dstlen, srclen, fmt);
	} else if(fmt & (sinsp_evt::PF_EOLS | sinsp_evt::PF_EOLS_COMPACT)) {
		k = binary_buffer_to_asciionly_string(dst, src, dstlen, srclen, fmt);
	} else {
		k = binary_buffer_to_string_dots(dst, src, dstlen, srclen, fmt);
	}

	dst[k] = 0;
	return k;
}

// `dst` and `src` must both be non-empty.
static void strcpy_sanitized(std::vector<char> &dst, const std::string_view src) {
	auto *dst_ptr = reinterpret_cast<unsigned char *>(&dst[0]);
	const auto dst_size = dst.size();
	ASSERT(dst_size > 0);

	const auto *src_ptr = reinterpret_cast<const unsigned char *>(src.data());
	const size_t src_size = src.size();
	ASSERT(src_size > 0);

	auto *capped_src_end = src_ptr + std::min(src_size, dst_size);

	// Find the first sequence in source needing replacement. For valid strings, this is the only
	// pass that runs (no replacement needed), and the flow immediately returns after copying the
	// maximum allowed amount of bytes.
	auto *scan_src_ptr = utf8_first_invalid_seq(src_ptr, capped_src_end);
	if(scan_src_ptr == capped_src_end) {
		size_t bytes_to_copy;
		if(src_size < dst_size) {
			bytes_to_copy = src_size;
		} else {
			// The source string must be truncated (`src_size >= dst_size`). Find the boundary of
			// the last valid UTF-8 sequence in source (a valid UTF-8 sequence is guaranteed to
			// exist, given `src_size > 0`).
			auto *scan_ptr = capped_src_end - 1;
			while(utf8_seq_len(scan_ptr, capped_src_end) < 0) {
				scan_ptr--;
			}
			const auto last_valid_seq_off = capped_src_end - scan_ptr;
			bytes_to_copy = dst_size - last_valid_seq_off;
		}
		memcpy(dst_ptr, src_ptr, bytes_to_copy);
		dst_ptr[bytes_to_copy] = 0;
		return;
	}

	// Copy the valid prefix (note: can be empty) in one shot.
	size_t bytes_to_copy = scan_src_ptr - src_ptr;
	memcpy(dst_ptr, src_ptr, bytes_to_copy);

	// Process the remainder. The assumption here is that, at the beginning of each iteration, there
	// is an invalid sequence in source that should result into a single replacement character into
	// destination: this requires at least 3 bytes for the replacement character. Moreover, the
	// destination must be NUL terminated, so the destination must have at least 4 bytes (i.e.:
	// `dst_left_bytes >= 4`).
	auto *scan_dst_ptr = dst_ptr + bytes_to_copy;
	size_t dst_left_bytes = dst_size - bytes_to_copy;
	while(scan_src_ptr < capped_src_end && dst_left_bytes >= 4) {
		// Replace the invalid sequence at the beginning of each iteration with the replacement
		// character.
		const int seq_len = utf8_seq_len(scan_src_ptr, capped_src_end);
		ASSERT(seq_len < 0);
		memcpy(scan_dst_ptr, "\xEF\xBF\xBD", 3);
		scan_dst_ptr += 3;
		dst_left_bytes -= 3;
		scan_src_ptr += -seq_len;

		// Find the next valid block of UTF-8 characters to copy. Its size must not be greater than
		// `min(src_left_bytes, dst_left_bytes - 1)`. (-1 accounts for the NUL terminator).
		const size_t src_left_bytes = capped_src_end - scan_src_ptr;
		const auto *end_ptr = scan_src_ptr + std::min(dst_left_bytes - 1, src_left_bytes);
		const auto *next_invalid = utf8_first_invalid_seq(scan_src_ptr, end_ptr);
		bytes_to_copy = next_invalid - scan_src_ptr;
		if(bytes_to_copy > 0) {
			memcpy(scan_dst_ptr, scan_src_ptr, bytes_to_copy);
			scan_dst_ptr += bytes_to_copy;
			dst_left_bytes -= bytes_to_copy;
		}
		scan_src_ptr = next_invalid;

		// `utf8_first_invalid_seq` could have stopped before the end of source due to the cap to
		// `dst_left_bytes - 1`. In this case, the following UTF-8 sequence could still be valid,
		// but there is no space left in the destination, so break.
		if(scan_src_ptr < capped_src_end && utf8_seq_len(scan_src_ptr, capped_src_end) > 0) {
			break;
		}
	}
	*scan_dst_ptr = 0;
}

int sinsp_evt::render_fd_json(Json::Value *ret,
                              const int64_t fd,
                              const char ** /*resolved_str*/,
                              const param_fmt fmt) {
	sinsp_threadinfo *tinfo = get_thread_info();
	if(tinfo == nullptr) {
		return 0;
	}

	if(fd >= 0) {
		if(const auto *fdinfo = tinfo->get_fd(fd)) {
			const auto tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK || fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
			   fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK || fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK) {
				switch(fdinfo->get_l4proto()) {
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

			const char typestr[3] = {fmt & PF_SIMPLE ? static_cast<char>(0) : tch, ipprotoch, 0};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			std::string sanitized_name_storage;
			const auto sanitized_name = sanitize_string(fdinfo->m_name, sanitized_name_storage);

			(*ret)["typechar"] = typestr;
			(*ret)["name"] = sanitized_name.data();
		}
	} else if(fd == PPM_AT_FDCWD) {
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		(*ret)["name"] = "AT_FDCWD";
	} else {
		//
		// Resolve this as an errno
		//
		if(const std::string errstr(sinsp_utils::errno_to_str(static_cast<int32_t>(fd)));
		   errstr != "") {
			(*ret)["error"] = errstr;
			return 0;
		}
	}

	return 1;
}

char *sinsp_evt::render_fd(const int64_t fd, const char ** /*resolved_str*/, const param_fmt fmt) {
	//
	// Add the fd number
	//
	snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRId64, fd);

	sinsp_threadinfo *tinfo = get_thread_info();
	if(tinfo == nullptr) {
		//
		// no thread. Definitely can't resolve the fd, just return the number
		//
		return &m_paramstr_storage[0];
	}

	if(fd >= 0) {
		if(const auto *fdinfo = tinfo->get_fd(fd)) {
			const auto tch = fdinfo->get_typechar();
			char ipprotoch = 0;

			if(fdinfo->m_type == SCAP_FD_IPV4_SOCK || fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
			   fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK || fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK) {
				switch(fdinfo->get_l4proto()) {
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

			char typestr[3] = {fmt & PF_SIMPLE ? static_cast<char>(0) : tch, ipprotoch, 0};

			//
			// Make sure we remove invalid characters from the resolved name
			//
			std::string sanitized_name_storage;
			const auto sanitized_name = sanitize_string(fdinfo->m_name, sanitized_name_storage);

			//
			// Make sure the string will fit
			//
			if(sanitized_name.size() >= m_resolved_paramstr_storage.size()) {
				m_resolved_paramstr_storage.resize(sanitized_name.size() + 1);
			}

			snprintf(&m_resolved_paramstr_storage[0],
			         m_resolved_paramstr_storage.size(),
			         "<%s>%s",
			         typestr,
			         sanitized_name.data());
		}
	} else if(fd == PPM_AT_FDCWD) {
		//
		// `fd` can be AT_FDCWD on all *at syscalls
		//
		snprintf(&m_resolved_paramstr_storage[0], m_resolved_paramstr_storage.size(), "AT_FDCWD");
	} else {
		//
		// Resolve this as an errno
		//
		const std::string errstr(sinsp_utils::errno_to_str(static_cast<int32_t>(fd)));
		if(errstr != "") {
			snprintf(&m_resolved_paramstr_storage[0],
			         m_resolved_paramstr_storage.size(),
			         "%s",
			         errstr.c_str());
		}
	}

	return &m_paramstr_storage[0];
}

std::string sinsp_evt::get_base_dir(const uint32_t id, sinsp_threadinfo *tinfo) {
	std::string cwd = tinfo->get_cwd();

	const ppm_param_info *param_info = &m_info->params[id];

	// If it's a regular FSPATH, just return the thread's CWD
	if(param_info->type != PT_FSRELPATH) {
		ASSERT(param_info->type == PT_FSPATH);
		return cwd;
	}

	const uint64_t dirfd_id = reinterpret_cast<uint64_t>(param_info->info);
	if(dirfd_id >= m_info->nparams) {
		ASSERT(dirfd_id < m_info->nparams);
		return cwd;
	}

	// Ensure the index points to an actual FD
	if(const auto *dir_param_info = &m_info->params[dirfd_id]; dir_param_info->type != PT_FD) {
		return cwd;
	}

	const int64_t dirfd = get_param(dirfd_id)->as<int64_t>();

	// If the FD is special value PPM_AT_FDCWD, just use CWD
	if(dirfd == PPM_AT_FDCWD) {
		return cwd;
	}

	// If the previous param is a fd with a value other than AT_FDCWD, get the path to that fd and
	// use it in place of CWD
	return tinfo->get_path_for_dir_fd(dirfd);
}

const char *sinsp_evt::get_param_as_str(uint32_t id, const char **resolved_str, param_fmt fmt) {
	char *prfmt = nullptr;
	const ppm_param_info *param_info = nullptr;
	std::string_view s;
	uint8_t sockfamily;

	//
	// Make sure the params are actually loaded
	//
	if((m_flags & SINSP_EF_PARAMS_LOADED) == 0) {
		load_params();
		m_flags |= static_cast<uint32_t>(SINSP_EF_PARAMS_LOADED);
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

	if(!param->used_legacy_null_encoding() && param->len() == 0) {
		// Ideally, we should always <NA>, but this would break compatibility, so keep pushing NULL
		// for parameters that could already be empty before the scap-converter introduced the
		// notion of "empty parameters" for all types.
		// TODO(ekoops): consistently send the same value.
		switch(param_info->type) {
		case PT_BYTEBUF:
		case PT_SOCKTUPLE:
		case PT_FDLIST:
		case PT_CHARBUFARRAY:
		case PT_CHARBUF_PAIR_ARRAY:
		case PT_DYN: {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "NULL");
			break;
		}
		default: {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "<NA>");
			break;
		}
		}
		*resolved_str = &m_resolved_paramstr_storage[0];
		return &m_paramstr_storage[0];
	}

	//
	// Get the parameter information
	//
	std::optional<sinsp_evt_param> dyn_param;
	if(param_info->type == PT_DYN && param_info->info != nullptr) {
		const auto param_data = param->data();
		const auto param_len = param->len();
		uint8_t dyn_idx = 0;
		memcpy(&dyn_idx, param_data, sizeof(uint8_t));

		if(dyn_idx < param_info->ninfo) {
			auto dyn_params = static_cast<const ppm_param_info *>(param_info->info);

			dyn_param = sinsp_evt_param(param->m_evt,
			                            param->m_idx,
			                            param_data + sizeof(uint8_t),
			                            param_len - sizeof(uint8_t));

			param = std::addressof(*dyn_param);
			param_info = &dyn_params[dyn_idx];
		}
	}

	ppm_print_format param_fmt = m_info->params[id].fmt;

	switch(param_info->type) {
	case PT_INT8:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<int8_t>());
		break;
	case PT_INT16:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<int16_t>());
		break;
	case PT_INT32:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<int32_t>());
		break;
	case PT_INT64:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<int64_t>());
		break;
	case PT_FD: {
		int64_t fd = param->as<int64_t>();
		render_fd(fd, resolved_str, fmt);
		break;
	}
	case PT_PID: {
		snprintf(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%" PRId64,
		         param->as<int64_t>());

		sinsp_threadinfo *atinfo =
		        m_inspector->m_thread_manager->find_thread(param->as<int64_t>(), true).get();
		if(atinfo != nullptr) {
			std::string &tcomm = atinfo->m_comm;

			//
			// Make sure the string will fit
			//
			if(tcomm.size() >= m_resolved_paramstr_storage.size()) {
				m_resolved_paramstr_storage.resize(tcomm.size() + 1);
			}

			snprintf(&m_resolved_paramstr_storage[0],
			         m_resolved_paramstr_storage.size(),
			         "%s",
			         tcomm.c_str());
		}
	} break;
	case PT_UINT8:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo8, PRId8, PRIX8);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<uint8_t>());
		break;
	case PT_UINT16:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo16, PRId16, PRIX16);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<uint16_t>());
		break;
	case PT_UINT32:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<uint32_t>());
		break;
	case PT_ERRNO: {
		int64_t val = param->as<int64_t>();

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRId64, val);

		//
		// Resolve this as an errno
		//
		std::string errstr;

		if(val < 0) {
			errstr = sinsp_utils::errno_to_str(static_cast<int32_t>(val));

			if(errstr != "") {
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "%s",
				         errstr.c_str());
			}
		}
	} break;
	case PT_UINT64:
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo64, PRId64, PRIX64);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, param->as<int64_t>());

		break;
	case PT_CHARBUF:
		//
		// Make sure the string will fit
		//
		s = param->as<std::string_view>();
		if(s.length() + 1 > m_paramstr_storage.size()) {
			m_paramstr_storage.resize(s.length() + 1);
		}

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%s", s.data());
		break;
	case PT_FSPATH:
	case PT_FSRELPATH: {
		const auto path = param->as<std::string_view>();
		if(path.length() + 1 > m_paramstr_storage.size()) {
			m_paramstr_storage.resize(path.length() + 1);
		}

		strcpy_sanitized(m_paramstr_storage, path);

		if(auto *tinfo = get_thread_info()) {
			if(path != "<NA>") {
				std::string cwd = get_base_dir(id, tinfo);

				if(path.length() + cwd.length() + 1 >= m_resolved_paramstr_storage.size()) {
					m_resolved_paramstr_storage.resize(path.length() + cwd.length() + 2, 0);
				}

				if(path.empty() || std::filesystem::path(path).is_absolute()) {
					m_resolved_paramstr_storage[0] = 0;
				} else {
					std::string concatenated_path = sinsp_utils::concatenate_paths(cwd, path);
					strcpy_sanitized(m_resolved_paramstr_storage, concatenated_path);
				}
			}
		} else {
			*resolved_str = &m_paramstr_storage[0];
		}
	} break;
	case PT_BYTEBUF: {
		auto param_data = param->data();
		auto param_len = param->len();
		while(true) {
			uint32_t blen =
			        binary_buffer_to_string(&m_paramstr_storage[0],
			                                param_data,
			                                static_cast<uint32_t>(m_paramstr_storage.size()) - 1,
			                                param_len,
			                                fmt);

			if(blen >= m_paramstr_storage.size() - 1) {
				//
				// The buffer didn't fit, expand it and try again
				//
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			ASSERT(m_inspector != nullptr);
			if(m_inspector->get_max_evt_output_len() != 0 &&
			   blen > m_inspector->get_max_evt_output_len() && fmt == PF_NORMAL) {
				uint32_t real_len = std::min(blen, m_inspector->get_max_evt_output_len());

				m_rawbuf_str_len = real_len;
				if(real_len > 3) {
					m_paramstr_storage[real_len - 3] = '.';
					m_paramstr_storage[real_len - 2] = '.';
					m_paramstr_storage[real_len - 1] = '.';
				}

				m_paramstr_storage[real_len] = 0;
			} else {
				m_rawbuf_str_len = blen;
			}
			break;
		}
	} break;
	case PT_SOCKADDR: {
		auto param_data = param->data();
		auto param_len = param->len();
		sockfamily = param_data[0];
		if(sockfamily == PPM_AF_UNIX) {
			ASSERT(param->len() > 1);

			//
			// Sanitize the file string.
			//
			std::string sanitized_path_storage;
			const auto sanitized_path = sanitize_string(param_data + 1, sanitized_path_storage);
			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "%s",
			         sanitized_path.data());
		} else if(sockfamily == PPM_AF_INET) {
			if(param_len == 1 + 4 + 2) {
				ipv4serverinfo addr;
				memcpy(&addr.m_ip, param_data + 1, sizeof(addr.m_ip));
				memcpy(&addr.m_port, param_data + 5, sizeof(addr.m_port));
				addr.m_l4proto = m_fdinfo != nullptr ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr = ipv4serveraddr_to_string(
				        addr,
				        m_inspector->is_hostname_and_port_resolution_enabled());
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%s", straddr.c_str());
			} else {
				ASSERT(false);
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "INVALID IPv4");
			}
		} else if(sockfamily == PPM_AF_INET6) {
			if(param_len == 1 + 16 + 2) {
				ipv6serverinfo addr;
				memcpy(addr.m_ip.m_b, param_data + 1, sizeof(addr.m_ip.m_b));
				memcpy(&addr.m_port, param_data + 17, sizeof(addr.m_port));
				addr.m_l4proto = m_fdinfo != nullptr ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr = ipv6serveraddr_to_string(
				        addr,
				        m_inspector->is_hostname_and_port_resolution_enabled());
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%s", straddr.c_str());
			} else {
				ASSERT(false);
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "INVALID IPv6");
			}
		} else {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "family %d", sockfamily);
		}
		break;
	}
	case PT_SOCKTUPLE: {
		const auto param_data = reinterpret_cast<const uint8_t *>(param->data());
		const auto param_len = param->len();
		sockfamily = param_data[0];
		if(sockfamily == PPM_AF_INET) {
			if(param_len == 1 + 4 + 2 + 4 + 2) {
				ipv4tuple addr;
				memcpy(&addr.m_fields.m_sip, param_data + 1, sizeof(uint32_t));
				memcpy(&addr.m_fields.m_sport, param_data + 5, sizeof(uint16_t));
				memcpy(&addr.m_fields.m_dip, param_data + 7, sizeof(uint32_t));
				memcpy(&addr.m_fields.m_dport, param_data + 11, sizeof(uint16_t));
				addr.m_fields.m_l4proto =
				        m_fdinfo != nullptr ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
				std::string straddr =
				        ipv4tuple_to_string(addr,
				                            m_inspector->is_hostname_and_port_resolution_enabled());
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%s", straddr.c_str());
			} else {
				ASSERT(false);
				snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "INVALID IPv4");
			}
		} else if(sockfamily == PPM_AF_INET6) {
			if(param_len == 1 + 16 + 2 + 16 + 2) {
				const uint8_t *sip6 = param_data + 1;
				const uint8_t *dip6 = param_data + 19;
				const uint8_t *sip = param_data + 13;
				const uint8_t *dip = param_data + 31;

				if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) &&
				   sinsp_utils::is_ipv4_mapped_ipv6(dip6)) {
					ipv4tuple addr;
					memcpy(&addr.m_fields.m_sip, sip, sizeof(uint32_t));
					memcpy(&addr.m_fields.m_sport, param_data + 17, sizeof(uint16_t));
					memcpy(&addr.m_fields.m_dip, dip, sizeof(uint32_t));
					memcpy(&addr.m_fields.m_dport, param_data + 35, sizeof(uint16_t));
					addr.m_fields.m_l4proto =
					        m_fdinfo != nullptr ? m_fdinfo->get_l4proto() : SCAP_L4_UNKNOWN;
					std::string straddr = ipv4tuple_to_string(
					        addr,
					        m_inspector->is_hostname_and_port_resolution_enabled());

					snprintf(&m_paramstr_storage[0],
					         m_paramstr_storage.size(),
					         "%s",
					         straddr.c_str());
					break;
				}
				char srcstr[INET6_ADDRSTRLEN];
				char dststr[INET6_ADDRSTRLEN];
				if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
				   inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr))) {
					uint16_t srcport, dstport;
					memcpy(&srcport, param_data + 17, sizeof(srcport));
					memcpy(&dstport, param_data + 35, sizeof(dstport));
					snprintf(&m_paramstr_storage[0],
					         m_paramstr_storage.size(),
					         "%s:%s->%s:%s",
					         srcstr,
					         port_to_string(srcport,
					                        m_fdinfo != nullptr ? m_fdinfo->get_l4proto()
					                                            : SCAP_L4_UNKNOWN,
					                        m_inspector->is_hostname_and_port_resolution_enabled())
					                 .c_str(),
					         dststr,
					         port_to_string(dstport,
					                        m_fdinfo != nullptr ? m_fdinfo->get_l4proto()
					                                            : SCAP_L4_UNKNOWN,
					                        m_inspector->is_hostname_and_port_resolution_enabled())
					                 .c_str());
					break;
				}
			}

			ASSERT(false);
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "INVALID IPv6");
		} else if(sockfamily == PPM_AF_UNIX) {
			ASSERT(param->len() > 17);

			//
			// Sanitize the file string.
			//
			std::string sanitized_path_storage;
			const auto sanitized_path =
			        sanitize_string(reinterpret_cast<const char *>(param_data) + 17,
			                        sanitized_path_storage);

			uint64_t src, dst;
			memcpy(&src, param_data + 1, sizeof(uint64_t));
			memcpy(&dst, param_data + 9, sizeof(uint64_t));

			snprintf(&m_paramstr_storage[0],
			         m_paramstr_storage.size(),
			         "%" PRIx64 "->%" PRIx64 " %s",
			         src,
			         dst,
			         sanitized_path.data());
		} else {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "family %d", sockfamily);
		}
		break;
	}
	case PT_FDLIST: {
		uint32_t j = 0;
		sinsp_threadinfo *tinfo = get_thread_info();
		if(!tinfo) {
			break;
		}

		const auto param_data = param->data();
		uint16_t nfds = 0;
		memcpy(&nfds, param_data, sizeof(nfds));
		uint32_t pos = 2;
		uint32_t spos = 0;

		m_paramstr_storage[0] = 0;

		for(j = 0; j < nfds; j++) {
			char tch;
			int64_t fd = 0;
			memcpy(&fd, param_data + pos, sizeof(uint64_t));

			if(const auto *fdinfo = tinfo->get_fd(fd)) {
				tch = fdinfo->get_typechar();
			} else {
				tch = '?';
			}

			int16_t p8;
			memcpy(&p8, param_data + pos + 8, sizeof(int16_t));

			int r = snprintf(&m_paramstr_storage[0] + spos,
			                 m_paramstr_storage.size() - spos,
			                 "%" PRIu64 ":%c%x%c",
			                 fd,
			                 tch,
			                 static_cast<uint32_t>(p8),
			                 j < static_cast<uint32_t>(nfds - 1) ? ' ' : '\0');

			if(r < 0 || spos + r >= m_paramstr_storage.size() - 1) {
				m_paramstr_storage[m_paramstr_storage.size() - 1] = 0;
				break;
			}

			spos += r;
			pos += 10;
		}
	} break;
	case PT_SYSCALLID: {
		uint16_t ppm_sc = param->as<uint16_t>();
		if(ppm_sc >= PPM_SC_MAX) {
			ASSERT(false);
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "<unknown syscall>");
			break;
		}

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRIu16, ppm_sc);

		snprintf(&m_resolved_paramstr_storage[0],
		         m_resolved_paramstr_storage.size(),
		         "%s",
		         scap_get_ppm_sc_name(static_cast<ppm_sc_code>(ppm_sc)));
	} break;
	case PT_SIGTYPE: {
		const char *sigstr;

		uint8_t val = param->as<uint8_t>();

		sigstr = sinsp_utils::signal_to_str(val);

		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRIu8, val);

		if(sigstr) {
			snprintf(&m_resolved_paramstr_storage[0],
			         m_resolved_paramstr_storage.size(),
			         "%s",
			         sigstr);
		}
	} break;
	case PT_RELTIME: {
		std::string sigstr;

		if(const auto val = param->as<uint64_t>(); val == static_cast<uint64_t>(-1)) {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "none");
			m_resolved_paramstr_storage[0] = '\0';
		} else {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRIu64, val);
			snprintf(&m_resolved_paramstr_storage[0],
			         m_resolved_paramstr_storage.size(),
			         "%lgs",
			         static_cast<double>(val) / 1000000000);
		}
	} break;
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
	case PT_ENUMFLAGS8:
	case PT_ENUMFLAGS16:
	case PT_ENUMFLAGS32: {
		uint32_t val = 0;
		switch(param_info->type) {
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
		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%" PRIu32, val);

		auto flags = static_cast<const ppm_name_value *>(m_info->params[id].info);
		const bool exact_match = param_info->type == PT_ENUMFLAGS8 ||
		                         param_info->type == PT_ENUMFLAGS16 ||
		                         param_info->type == PT_ENUMFLAGS32;
		auto separator = "";
		uint32_t initial_val = val;
		uint32_t j = 0;

		while(flags != nullptr && flags->name != nullptr) {
			bool match = false;
			if(exact_match) {
				match = flags->value == initial_val;
			} else {
				// If flag is 0, then initial_val needs to be 0 for the flag to be resolved
				if((flags->value == 0 && initial_val == 0) ||
				   (flags->value != 0 && (val & flags->value) == flags->value && val != 0)) {
					match = true;
					// We remove current flags value to avoid duplicate flags e.g. PPM_O_RDWR,
					// PPM_O_RDONLY, PPM_O_WRONLY
					val &= ~flags->value;
				}
			}
			if(match) {
				if(m_resolved_paramstr_storage.size() <
				   j + strlen(separator) + strlen(flags->name)) {
					m_resolved_paramstr_storage.resize(m_resolved_paramstr_storage.size() * 2);
				}

				j += snprintf(&m_resolved_paramstr_storage[j],
				              m_resolved_paramstr_storage.size(),
				              "%s%s",
				              separator,
				              flags->name);
				separator = "|";
				if(!exact_match) {
					if(flags->value == initial_val) {
						// if we reached initial val, we have finished.
						// NOTE: for enum flags, we might have multiple flags matching same enum
						// value see socket_families (eg: AF_LOCAL, AF_UNIX). Don't break.
						break;
					}
				}
			}

			flags++;
		}

		break;
	}
	case PT_MODE: {
		uint32_t val = param->as<uint32_t>();
		SET_NUMERIC_FORMAT(prfmt, param_fmt, PRIo32, PRId32, PRIX32);
		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), prfmt, val);

		auto mode = static_cast<const ppm_name_value *>(m_info->params[id].info);
		auto separator = "";
		uint32_t initial_val = val;
		uint32_t j = 0;

		while(mode != nullptr && mode->name != nullptr && mode->value != initial_val) {
			// If mode is 0, then initial_val needs to be 0 for the mode to be resolved
			if((mode->value == 0 && initial_val == 0) ||
			   (mode->value != 0 && (val & mode->value) == mode->value && val != 0)) {
				if(size_t params_len = j + strlen(separator) + strlen(mode->name);
				   m_resolved_paramstr_storage.size() < params_len) {
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

		if(mode != nullptr && mode->name != nullptr) {
			j += snprintf(&m_resolved_paramstr_storage[j],
			              m_resolved_paramstr_storage.size(),
			              "%s%s",
			              separator,
			              mode->name);
		}

		break;
	}
	case PT_ABSTIME: {
		uint64_t val = param->as<uint64_t>();
		time_t sec = val / 1000000000ULL;
		unsigned long nsec = val % 1000000000ULL;
		tm tm;
		localtime_r(&sec, &tm);
		strftime(&m_paramstr_storage[0],
		         m_paramstr_storage.size(),
		         "%Y-%m-%d %H:%M:%S.XXXXXXXXX %z",
		         &tm);
		snprintf(&m_paramstr_storage[20], 10, "%09ld", nsec);
		break;
	}
	case PT_DYN:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "INVALID DYNAMIC PARAMETER");
		break;
	case PT_UID: {
		if(const auto val = param->as<uint32_t>(); val < std::numeric_limits<uint32_t>::max()) {
			// Note: we want to resolve user given the uid
			// from the event.
			// Eg: for setuid() the requested uid is not
			// the threadinfo one yet;
			// therefore we cannot directly use tinfo->m_user here.
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%d", val);
			sinsp_threadinfo *tinfo = get_thread_info();
			scap_userinfo *user_info = nullptr;
			if(tinfo) {
				auto container_id = m_inspector->m_plugin_tables.get_container_id(*tinfo);
				user_info = m_inspector->m_usergroup_manager->get_user(container_id, val);
			}
			if(user_info != nullptr && user_info->name[0] != 0) {
				strcpy_sanitized(m_resolved_paramstr_storage, user_info->name);
			} else {
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "<NA>");
			}
		} else {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "-1");
			snprintf(&m_resolved_paramstr_storage[0], m_resolved_paramstr_storage.size(), "<NONE>");
		}
		break;
	}
	case PT_GID: {
		if(const auto val = param->as<uint32_t>(); val < std::numeric_limits<uint32_t>::max()) {
			// Note: we want to resolve group given the gid
			// from the event.
			// Eg: for setgid() the requested gid is not
			// the threadinfo one yet;
			// therefore we cannot directly use tinfo->m_group here.
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "%d", val);
			sinsp_threadinfo *tinfo = get_thread_info();
			scap_groupinfo *group_info = nullptr;
			if(tinfo) {
				auto container_id = m_inspector->m_plugin_tables.get_container_id(*tinfo);
				group_info = m_inspector->m_usergroup_manager->get_group(container_id, val);
			}
			if(group_info != nullptr && group_info->name[0] != 0) {
				strcpy_sanitized(m_resolved_paramstr_storage, group_info->name);
			} else {
				snprintf(&m_resolved_paramstr_storage[0],
				         m_resolved_paramstr_storage.size(),
				         "<NA>");
			}
		} else {
			snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "-1");
			snprintf(&m_resolved_paramstr_storage[0], m_resolved_paramstr_storage.size(), "<NONE>");
		}
		break;
	}
	case PT_CHARBUFARRAY: {
		ASSERT(param->len() == sizeof(uint64_t));
		auto *strvect = reinterpret_cast<std::vector<char *> *>(
		        *reinterpret_cast<const uint64_t *>(param->data()));

		m_paramstr_storage[0] = 0;

		while(true) {
			std::vector<char *>::iterator it;
			std::vector<char *>::iterator itbeg;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char *dst = &m_paramstr_storage[0];
			char *dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it = itbeg = strvect->begin(); it != strvect->end(); ++it) {
				char *src = *it;

				if(it != itbeg) {
					if(dst < dstend - 1) {
						*dst++ = '.';
					}
				}

				while(*src != 0 && dst < dstend) {
					*dst++ = *src++;
				}

				if(dst == dstend) {
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize) {
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}
	} break;
	case PT_CHARBUF_PAIR_ARRAY: {
		ASSERT(param->len() == sizeof(uint64_t));
		auto *pairs = reinterpret_cast<std::pair<std::vector<char *> *, std::vector<char *> *> *>(
		        *reinterpret_cast<const uint64_t *>(param->data()));

		m_paramstr_storage[0] = 0;

		if(pairs->first->size() != pairs->second->size()) {
			ASSERT(false);
			break;
		}

		while(true) {
			std::vector<char *>::iterator it1;
			std::vector<char *>::iterator itbeg1;
			std::vector<char *>::iterator it2;
			bool need_to_resize = false;

			//
			// Copy the arguments
			//
			char *dst = &m_paramstr_storage[0];
			char *dstend = &m_paramstr_storage[0] + m_paramstr_storage.size() - 2;

			for(it1 = itbeg1 = pairs->first->begin(), it2 = pairs->second->begin();
			    it1 != pairs->first->end();
			    ++it1, ++it2) {
				char *src = *it1;

				if(it1 != itbeg1) {
					if(dst < dstend - 1) {
						*dst++ = ',';
					}
				}

				//
				// Copy the first string
				//
				while(*src != 0 && dst < dstend) {
					*dst++ = *src++;
				}

				if(dst < dstend - 1) {
					*dst++ = ':';
				}

				//
				// Copy the second string
				//
				src = *it2;
				while(*src != 0 && dst < dstend) {
					*dst++ = *src++;
				}

				if(dst == dstend) {
					//
					// Reached the end of m_paramstr_storage, we need to resize it
					//
					need_to_resize = true;
					break;
				}
			}

			if(need_to_resize) {
				m_paramstr_storage.resize(m_paramstr_storage.size() * 2);
				continue;
			}

			*dst = 0;

			break;
		}

		break;
	}
	case PT_SIGSET: {
		uint32_t val = param->as<uint32_t>();

		m_resolved_paramstr_storage[0] = '\0';
		m_paramstr_storage[0] = '\0';

		char *storage = &m_paramstr_storage[0];
		int remaining = static_cast<int>(m_paramstr_storage.size());
		bool first = true;

		for(int sig = 0; sig < 32; sig++) {
			if(val & 1U << sig) {
				if(const auto *sigstr = sinsp_utils::signal_to_str(sig + 1)) {
					int printed = snprintf(storage, remaining, "%s%s", !first ? " " : "", sigstr);
					if(printed >= remaining) {
						storage[remaining - 1] = '\0';
						break;
					}

					first = false;
					storage += printed;
					remaining -= printed;
				}
			}
		}
		break;
	}
	default:
		ASSERT(false);
		snprintf(&m_paramstr_storage[0], m_paramstr_storage.size(), "(n.a.)");
		break;
	}

	*resolved_str = &m_resolved_paramstr_storage[0];

	return &m_paramstr_storage[0];
}

std::string sinsp_evt::get_param_value_str(const std::string_view name, const bool resolved) {
	for(uint32_t i = 0; i < get_num_params(); i++) {
		if(name == get_param_name(i)) {
			return get_param_value_str(i, resolved);
		}
	}

	return std::string();
}

std::string sinsp_evt::get_param_value_str(const uint32_t id, const bool resolved) {
	const char *param_value_str;
	const char *val_str = get_param_as_str(id, &param_value_str);
	if(resolved) {
		return std::string(*param_value_str == '\0' ? val_str : param_value_str);
	}
	return std::string(val_str);
}

const char *sinsp_evt::get_param_value_str(std::string_view name,
                                           const char **resolved_str,
                                           const param_fmt fmt) {
	for(uint32_t i = 0; i < get_num_params(); i++) {
		if(name == get_param_name(i)) {
			return get_param_as_str(i, resolved_str, fmt);
		}
	}

	*resolved_str = nullptr;
	return nullptr;
}

void sinsp_evt::get_category(category *cat) const {
	/* We always search the category inside the event table */
	cat->m_category = get_category();

	//
	// For EC_IO and EC_WAIT events, we dig into the fd state to get the category
	// and fdtype
	//
	if(cat->m_category & EC_IO_BASE) {
		if(!m_fdinfo) {
			//
			// The fd info is not present, likely because we missed its creation.
			//
			cat->m_subcategory = SC_UNKNOWN;
			return;
		}
		switch(m_fdinfo->m_type) {
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
	} else {
		cat->m_subcategory = SC_NONE;
	}
}

bool sinsp_evt::is_filtered_out() const {
	return m_filtered_out;
}

scap_dump_flags sinsp_evt::get_dump_flags(bool *should_drop) const {
	uint32_t dflags = SCAP_DF_NONE;
	*should_drop = false;

	if(m_filtered_out) {
		if(m_inspector->is_fatfile_enabled()) {
			if(const auto eflags = get_info_flags(); eflags & EF_MODIFIES_STATE) {
				dflags = SCAP_DF_STATE_ONLY;
			} else {
				*should_drop = true;
			}
		} else {
			*should_drop = true;
		}

		if(*should_drop) {
			if(const auto ecat = get_category(); ecat & EC_INTERNAL) {
				*should_drop = false;
			}
		}
	}

	if(get_info_flags() & EF_LARGE_PAYLOAD) {
		dflags |= SCAP_DF_LARGE;
	}

	return static_cast<scap_dump_flags>(dflags);
}

bool sinsp_evt::is_syscall_error() const {
	return m_errorcode != 0 && m_errorcode != SE_EINPROGRESS && m_errorcode != SE_EAGAIN &&
	       m_errorcode != SE_ETIMEDOUT;
}

bool sinsp_evt::is_file_open_error() const {
	return m_fdinfo == nullptr &&
	       (m_pevt->type == PPME_SYSCALL_OPEN_X || m_pevt->type == PPME_SYSCALL_CREAT_X ||
	        m_pevt->type == PPME_SYSCALL_OPENAT_2_X || m_pevt->type == PPME_SYSCALL_OPENAT2_X ||
	        m_pevt->type == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X);
}

bool sinsp_evt::is_file_error() const {
	return is_file_open_error() || (m_fdinfo != nullptr && (m_fdinfo->m_type == SCAP_FD_FILE ||
	                                                        m_fdinfo->m_type == SCAP_FD_FILE_V2));
}

bool sinsp_evt::is_network_error() const {
	if(m_fdinfo != nullptr) {
		return m_fdinfo->m_type == SCAP_FD_IPV4_SOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SOCK;
	}
	return m_pevt->type == PPME_SOCKET_ACCEPT_5_X || m_pevt->type == PPME_SOCKET_ACCEPT4_6_X ||
	       m_pevt->type == PPME_SOCKET_CONNECT_X || m_pevt->type == PPME_SOCKET_BIND_X;
}

uint64_t sinsp_evt::get_lastevent_ts() const {
	return m_tinfo->m_lastevent_ts;
}

void sinsp_evt_param::throw_invalid_len_error(const size_t requested_len) const {
	const auto param_data = data();
	const auto param_len = len();
	const ppm_param_info *parinfo = get_info();

	std::stringstream ss;
	ss << "could not parse param " << m_idx << " (" << parinfo->name << ") for event "
	   << m_evt->get_num() << " of type " << m_evt->get_type() << " (" << m_evt->get_name()
	   << "), for tid " << m_evt->get_tid() << ": expected length " << requested_len << ", found "
	   << param_len;
	const std::string error_string = ss.str();
	libsinsp_logger()->log(error_string, sinsp_logger::SEV_ERROR);
	libsinsp_logger()->log(
	        "parameter raw data: \n" + buffer_to_multiline_hex(param_data, param_len),
	        sinsp_logger::SEV_ERROR);

	throw sinsp_exception(error_string);
}

const ppm_param_info *sinsp_evt_param::get_info() const {
	return &m_evt->get_info()->params[m_idx];
}
