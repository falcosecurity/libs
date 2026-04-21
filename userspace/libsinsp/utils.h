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

#include <libscap/scap.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/tuples.h>

#include <json/json.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <locale>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

class sinsp_evttables;
union sinsp_sockinfo;
class filter_check_info;

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// Initializer class.
// An instance of this class is created when the library is loaded.
// ONE-SHOT INIT-TIME OPERATIONS SHOULD BE DONE IN THE CONSTRUCTOR OF THIS
// CLASS TO KEEP THEM UNDER A SINGLE PLACE.
///////////////////////////////////////////////////////////////////////////////
class sinsp_initializer {
public:
	sinsp_initializer();
};

class sinsp_evt_param;

///////////////////////////////////////////////////////////////////////////////
// A collection of useful functions
///////////////////////////////////////////////////////////////////////////////
class sinsp_utils {
public:
	//
	// Convert an errno number into the corresponding compact code
	//
	static const char* errno_to_str(int32_t code);

	//
	// Convert a signal number into the corresponding signal name
	//
	static const char* signal_to_str(uint8_t code);

	//
	//
	//
	static bool sockinfo_to_str(sinsp_sockinfo* sinfo,
	                            scap_fd_type stype,
	                            char* targetbuf,
	                            size_t targetbuf_size,
	                            bool resolve = false);

	//
	// Check if string ends with another
	//
	static inline bool endswith(std::string_view str, std::string_view ending) {
		if(ending.size() <= str.size()) {
			return (0 == str.compare(str.length() - ending.length(), ending.length(), ending));
		}
		return false;
	}

	static inline bool endswith(const char* str, const char* ending, uint32_t lstr, uint32_t lend) {
		if(lstr >= lend) {
			return (0 == memcmp(ending, str + (lstr - lend), lend));
		}
		return 0;
	}

	//
	// Check if string starts with another
	//
	static bool startswith(std::string_view, std::string_view prefix);

	//
	// Transform a hex string into bytes
	//
	static bool unhex(std::string_view hex_chars, std::vector<char>& hex_bytes);

	//
	// Concatenate posix-style path1 and path2 up to max_len in size, normalizing the result.
	// path1 MUST be '/' terminated and is not sanitized.
	// If path2 is absolute, the result will be equivalent to path2.
	// If the result would be too long, the output will contain the string
	// "/DIR_TOO_LONG/FILENAME_TOO_LONG" instead.
	//
	static std::string concatenate_paths(std::string_view path1, std::string_view path2);

	//
	// Determines if an IPv6 address is IPv4-mapped
	//
	static bool is_ipv4_mapped_ipv6(const uint8_t* paddr);

	//
	// Given a string, scan the event list and find the longest argument that the input string
	// contains
	//
	static const ppm_param_info* find_longest_matching_evt_param(std::string_view name);

	static uint64_t get_current_time_ns();

	static bool glob_match(const char* pattern,
	                       const char* string,
	                       const bool& case_insensitive = false);

#ifndef _WIN32
	//
	// Print the call stack
	//
	static void bt(void);
#endif  // _WIN32

	/*
	 * \param res [out] the generated string representation of the provided timestamp
	 */
	static void ts_to_string(uint64_t ts, std::string* res, bool date, bool ns);

	/*
	 * \param res [out] the generated string representation of the provided timestamp
	 */
	static void ts_to_iso_8601(uint64_t ts, std::string* res);

	//
	// Convert caps from their numeric representation to a space-separated string list
	//
	static std::string caps_to_string(const uint64_t caps);

	static uint64_t get_max_caps();

	/// Validate that a sockaddr parameter has sufficient size for its address family.
	/// Returns false if the param is empty or too small for a known family.
	static bool is_sockaddr_valid(const sinsp_evt_param& param);

	/// Validate that a socktuple parameter has sufficient size for its address family.
	/// Returns false if the param is empty or too small for a known family.
	static bool is_socktuple_valid(const sinsp_evt_param& param);
};

///////////////////////////////////////////////////////////////////////////////
// little STL thing to sanitize strings
///////////////////////////////////////////////////////////////////////////////

struct g_invalidchar {
	bool operator()(char c) const {
		unsigned char uc = static_cast<unsigned char>(c);
		// Exclude all non-printable characters and control characters while
		// including a wide range of languages (emojis, cyrillic, chinese etc)
		return (!(isprint(uc)));
	}
};

// Returns a nonzero integer describing the UTF-8 sequence starting at `p`:
// - if > 0, indicates a valid and printable UTF-8 sequence; the returned value is the sequence
//   length (in range [1; 4]).
// - if < 0, indicates an invalid byte, a broken sequence, or a valid-but-non-printable sequence;
//   the absolute value is the number of bytes to consume (in range [1; 4]).
//
// Broken sequences follow the maximal subpart substitution algorithm (Unicode Standard §3.9, U+FFFD
// Substitution of Maximal Subparts): each continuation byte that falls within the valid range for
// its position extends the consumed subpart; the first byte that is out of range (or absent)
// truncates it. For example:
// - sequence: 3-byte lead + valid first continuation + bad second continuation; consumed: 2 bytes;
//   return value: -2
// - sequence: 3-byte lead + bad first continuation; consumed 1 byte; return value: -1
//
// Valid-but-non-printable sequences (C1 controls U+0080..U+009F, Unicode non-characters) are
// consumed in full (e.g. -2 for U+0085 = C2 85, -3 for U+FDD0 = EF B7 90).
// `p_end` is the exclusive upper bound of the source buffer.
inline int utf8_seq_len(const unsigned char* p, const unsigned char* p_end) {
	const unsigned char c = p[0];
	if(c < 0x80) {
		// ASCII: printable range is 0x20 (space) to 0x7E (tilde); reject control chars and DEL.
		return c >= 0x20 && c != 0x7F ? 1 : -1;
	}
	if(c < 0xC2) {
		// 0x80-0xBF: orphan continuation byte.
		// 0xC0-0xC1: would encode U+0000..U+007F (overlong 2-byte).
		return -1;
	}
	if(c < 0xE0) {
		// 2-byte: 110xxxxx 10xxxxxx. Need 1 continuation byte.
		if(p + 1 >= p_end || (p[1] & 0xC0) != 0x80) {
			return -1;
		}
		const unsigned int cp =
		        static_cast<unsigned int>(c & 0x1F) << 6 | static_cast<unsigned int>(p[1] & 0x3F);
		// Reject C1 control characters (U+0080..U+009F) (non-printable).
		return cp > 0x9F ? 2 : -2;
	}
	if(c < 0xF0) {
		// 3-byte: 1110xxxx 10xxxxxx 10xxxxxx.
		// Enforce lead-byte-specific valid ranges for the first continuation byte: 0xE0 requires
		// 0xA0-0xBF (to structurally exclude overlongs), 0xED requires 0x80-0x9F (to structurally
		// exclude surrogates). When the first continuation is out of range, only the lead byte is
		// the maximal subpart (-1); when the second continuation is bad, the lead plus the valid
		// first continuation form the maximal subpart (-2).
		const unsigned char lo2 = c == 0xE0 ? 0xA0u : 0x80u;
		const unsigned char hi2 = c == 0xED ? 0x9Fu : 0xBFu;
		if(p + 1 >= p_end || p[1] < lo2 || p[1] > hi2) {
			return -1;  // Maximal subpart: lead byte only.
		}
		if(p + 2 >= p_end || (p[2] & 0xC0) != 0x80) {
			return -2;  // Maximal subpart: lead + first continuation.
		}
		const unsigned int cp = static_cast<unsigned int>(c & 0x0F) << 12 |
		                        static_cast<unsigned int>(p[1] & 0x3F) << 6 |
		                        static_cast<unsigned int>(p[2] & 0x3F);
		// Overlongs and surrogates are structurally excluded by the narrow ranges above.
		// Reject Unicode non-characters (U+FDD0-U+FDEF, U+FFFE-U+FFFF).
		if((cp >= 0xFDD0 && cp <= 0xFDEF) || cp >= 0xFFFE) {
			return -3;
		}
		return 3;
	}
	if(c <= 0xF4) {
		// 4-byte: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx.
		// Enforce lead-byte-specific valid ranges for the first continuation byte: 0xF0 requires
		// 0x90-0xBF (to structurally exclude overlongs), 0xF4 requires 0x80-0x8F (to structurally
		// exclude > U+10FFFF). 0xF5-0xFF are never valid and fall through to the catch-all below.
		// Maximal subpart grows by one byte for each valid continuation position consumed.
		const unsigned char lo2 = c == 0xF0 ? 0x90u : 0x80u;
		const unsigned char hi2 = c == 0xF4 ? 0x8Fu : 0xBFu;
		if(p + 1 >= p_end || p[1] < lo2 || p[1] > hi2) {
			return -1;  // Maximal subpart: lead byte only.
		}
		if(p + 2 >= p_end || (p[2] & 0xC0) != 0x80) {
			return -2;  // Maximal subpart: lead + first continuation.
		}
		if(p + 3 >= p_end || (p[3] & 0xC0) != 0x80) {
			return -3;  // Maximal subpart: lead + first + second continuation.
		}
		const unsigned int cp = static_cast<unsigned int>(c & 0x07) << 18 |
		                        static_cast<unsigned int>(p[1] & 0x3F) << 12 |
		                        static_cast<unsigned int>(p[2] & 0x3F) << 6 |
		                        static_cast<unsigned int>(p[3] & 0x3F);
		// Overlongs and out-of-range values are structurally excluded by the narrow ranges above.
		// Reject end-of-plane non-characters (U+xFFFE, U+xFFFF for planes 1-16).
		if((cp & 0xFFFF) >= 0xFFFE) {
			return -4;
		}
		return 4;
	}

	// 0xF5-0xFF: never valid in UTF-8.
	return -1;
}

// Skips 8 printable ASCII bytes [0x20, 0x7E] at a time, until it finds a block of 8 bytes
// containing a single byte not in that range or until it finds a block (at the end of the string)
// shorter than 8 bytes. Returns the pointer to the next invalid block or to the final shorter
// block.
inline const unsigned char* skip_8_byte_printable_ascii_blocks(const unsigned char* ptr,
                                                               const unsigned char* end_ptr) {
	while(ptr + 8 <= end_ptr) {
		uint64_t word;
		memcpy(&word, ptr, 8);
		// Check all 8 bytes are printable ASCII [0x20, 0x7E] using word-at-a-time tricks.
		// Each condition isolates the highest bit of each byte (by masking it with 0x80).
		// Check 1: match any byte >= 0x80 (non-ASCII, having high bit == 1)
		// Check 2: adding 0x60 maps [0x00,0x1F] to [0x60,0x7F] (high bit == 0) and [0x20,0x7F] to
		//   [0x80,0xDF] (high bit == 1); no carry between bytes since all bytes are <= 0x7F after
		//   check 1, so max per-byte result is 0x7F+0x60=0xDF < 0x100; match any byte of the first
		//   group (high bit 0)
		// Check 3: match any byte == 0x7F (DEL): adding 0x01 maps 0x7F to 0x80 (high bit == 1)
		if(word & 0x8080808080808080ULL ||
		   ((word + 0x6060606060606060ULL) & 0x8080808080808080ULL) != 0x8080808080808080ULL ||
		   (word + 0x0101010101010101ULL) & 0x8080808080808080ULL) {
			break;
		}
		ptr += 8;
	}
	return ptr;
}

inline void sanitize_string(std::string& str) {
	const auto* const str_ptr = reinterpret_cast<const unsigned char*>(str.data());
	const auto str_len = str.size();
	const auto* const str_end_ptr = str_ptr + str_len;

	// First pass (note: this must be FAST).
	// Find the first sequence needing replacement. For valid strings, this is the only pass that
	// runs (no replacement needed).
	auto* scan_ptr = str_ptr;
	while(scan_ptr < str_end_ptr) {
		// If `scan_ptr` is 8-byte aligned, try to fast-skip 8-byte printable ASCII blocks.
		if((reinterpret_cast<uintptr_t>(scan_ptr) & 7u) == 0u) {
			scan_ptr = skip_8_byte_printable_ascii_blocks(scan_ptr, str_end_ptr);
			if(scan_ptr >= str_end_ptr) {
				break;
			}
		}
		// Check if the next sequence needs to be replaced (i.e.: `seq_len` is negative).
		const int seq_len = utf8_seq_len(scan_ptr, str_end_ptr);
		if(seq_len < 0) {
			break;
		}
		scan_ptr += seq_len;
	}

	// String is already valid, return.
	if(scan_ptr == str_end_ptr) {
		return;
	}

	// Second pass for strings needing replacements (note: unfortunately, this is not as fast as the
	// first pass).
	// Copy the already-validated prefix in one shot, then process the remainder.
	std::string res;
	res.reserve(str_len);
	res.append(reinterpret_cast<const char*>(str_ptr), static_cast<size_t>(scan_ptr - str_ptr));

	// As we scan the string, keep track of the beginning of the last non-yet-copied block of
	// multiple valid UTF-8 sequences: in this way, we can append the entire block with a single
	// `res.append()` call.
	const auto* block_start = scan_ptr;
	do {
		// Process the current sequence first (on the first iteration this is the one that must be
		// replaced).
		if(const int seq_len = utf8_seq_len(scan_ptr, str_end_ptr); seq_len > 0) {
			scan_ptr += seq_len;
		} else {
			// Found invalid sequence. Copy the last valid block (if any) and then append the
			// replacement character.
			if(scan_ptr > block_start) {
				res.append(reinterpret_cast<const char*>(block_start),
				           static_cast<size_t>(scan_ptr - block_start));
			}
			res.append("\xEF\xBF\xBD", 3);
			scan_ptr += -seq_len;
			block_start = scan_ptr;
		}
		// If `scan_ptr` is now 8-byte aligned, try to fast-skip 8-byte printable ASCII blocks.
		if((reinterpret_cast<uintptr_t>(scan_ptr) & 7u) == 0u) {
			scan_ptr = skip_8_byte_printable_ascii_blocks(scan_ptr, str_end_ptr);
		}
	} while(scan_ptr < str_end_ptr);

	// Copy the last valid block (if any).
	if(scan_ptr > block_start) {
		res.append(reinterpret_cast<const char*>(block_start),
		           static_cast<size_t>(scan_ptr - block_start));
	}

	str = std::move(res);
}

inline void remove_duplicate_path_separators(std::string& str) {
	// Light fd name sanitization if fd is a file - only remove consecutive duplicate separators
	if(str.size() < 2) {
		// There is nothing to do if there are 0 or 1 chars in the string, protecting dereference
		// operations
		return;
	}

	char prev_char = *str.begin();

	for(auto cur_char_it = str.begin() + 1; cur_char_it != str.end();) {
		if(prev_char == *cur_char_it && prev_char == '/') {
			cur_char_it = str.erase(cur_char_it);
		} else {
			prev_char = *cur_char_it;
			cur_char_it++;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Time utility functions.
///////////////////////////////////////////////////////////////////////////////

time_t get_epoch_utc_seconds(const std::string& time_str,
                             const std::string& fmt = "%Y-%m-%dT%H:%M:%SZ");
time_t get_epoch_utc_seconds_now();

// Time functions for Windows

#ifdef _WIN32
struct timezone2 {
	int32_t tz_minuteswest;
	bool tz_dsttime;
};

SINSP_PUBLIC int gettimeofday(struct timeval* tv, struct timezone2* tz);
#endif  // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
std::string sinsp_gethostname();

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////

// each of these functions uses values in network byte order

std::string ipv4tuple_to_string(const ipv4tuple& tuple, bool resolve);
std::string ipv6tuple_to_string(const ipv6tuple& tuple, bool resolve);
std::string ipv4serveraddr_to_string(const ipv4serverinfo& addr, bool resolve);
std::string ipv6serveraddr_to_string(const ipv6serverinfo& addr, bool resolve);

// `l4proto` should be of type scap_l4_proto, but since it's an enum sometimes
// is used as int and we would have to cast
// `port` must be saved with network byte order
// `l4proto` could be neither TCP nor UDP, in this case any protocol will be
//           matched
std::string port_to_string(uint16_t port, uint8_t l4proto, bool resolve);

const char* param_type_to_string(ppm_param_type pt);
const char* print_format_to_string(ppm_print_format fmt);

///////////////////////////////////////////////////////////////////////////////
// String helpers
///////////////////////////////////////////////////////////////////////////////

// split a string into components separated by delim.
// An empty string in input will produce a vector with no elements.
std::vector<std::string> sinsp_split(std::string_view sv, char delim);

template<typename It>
std::string sinsp_join(It begin, It end, char delim) {
	if(begin == end) {
		return "";
	}
	std::stringstream ss;
	ss << *begin;
	++begin;
	for(auto it = begin; it != end; ++it) {
		ss << delim << *it;
	}
	return ss.str();
}

std::string& ltrim(std::string& s);
std::string& rtrim(std::string& s);
std::string& trim(std::string& s);

[[nodiscard]] std::string_view ltrim_sv(std::string_view);
[[nodiscard]] std::string_view rtrim_sv(std::string_view);
[[nodiscard]] std::string_view trim_sv(std::string_view);

std::string& replace_in_place(std::string& s,
                              const std::string& search,
                              const std::string& replacement);
std::string replace(const std::string& str,
                    const std::string& search,
                    const std::string& replacement);

std::string buffer_to_multiline_hex(const char* buf, size_t size);

///////////////////////////////////////////////////////////////////////////////
// number parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_numparser {
public:
	static uint8_t parseu8(const std::string& str);
	static int8_t parsed8(const std::string& str);
	static uint16_t parseu16(const std::string& str);
	static int16_t parsed16(const std::string& str);
	static uint32_t parseu32(const std::string& str);
	static int32_t parsed32(const std::string& str);
	static uint64_t parseu64(const std::string& str);
	static int64_t parsed64(const std::string& str);

	static bool tryparseu32(const std::string& str, uint32_t* res);
	static bool tryparsed32(const std::string& str, int32_t* res);
	static bool tryparseu64(const std::string& str, uint64_t* res);
	static bool tryparsed64(const std::string& str, int64_t* res);

	static bool tryparseu32_fast(const char* str, uint32_t strlen, uint32_t* res);
	static bool tryparsed32_fast(const char* str, uint32_t strlen, int32_t* res);
};

///////////////////////////////////////////////////////////////////////////////
// socket helpers
///////////////////////////////////////////////////////////////////////////////

bool set_socket_blocking(int sock, bool block);

unsigned int read_num_possible_cpus(void);

///////////////////////////////////////////////////////////////////////////////
// Log helpers
///////////////////////////////////////////////////////////////////////////////
void sinsp_scap_log_fn(const char* component,
                       const char* msg,
                       const enum falcosecurity_log_severity sev);

///////////////////////////////////////////////////////////////////////////////
// Set operation functions.
///////////////////////////////////////////////////////////////////////////////

template<typename T>
std::set<T> unordered_set_to_ordered(const std::unordered_set<T>& unordered_set);

template<typename T>
std::unordered_set<T> unordered_set_difference(const std::unordered_set<T>& a,
                                               const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_difference(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_union(const std::unordered_set<T>& a,
                                          const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_union(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_intersection(const std::unordered_set<T>& a,
                                                 const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_intersection(const std::set<T>& a, const std::set<T>& b);

std::string concat_set_in_order(const std::unordered_set<std::string>& s,
                                const std::string& delim = ", ");
std::string concat_set_in_order(const std::set<std::string>& s, const std::string& delim = ", ");
