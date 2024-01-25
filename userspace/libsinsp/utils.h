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
class sinsp_initializer
{
public:
	sinsp_initializer();
};

///////////////////////////////////////////////////////////////////////////////
// A collection of useful functions
///////////////////////////////////////////////////////////////////////////////
class sinsp_utils
{
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
	static bool sockinfo_to_str(sinsp_sockinfo* sinfo, scap_fd_type stype, char* targetbuf, uint32_t targetbuf_size, bool resolve = false);

	//
	// Check if string ends with another
	//
	static bool endswith(const std::string& str, const std::string& ending);
	static bool endswith(const char *str, const char *ending, uint32_t lstr, uint32_t lend);

	//
	// Check if string starts with another
	//
	static bool startswith(const std::string& s, const std::string& prefix);

	//
	// Transform a hex string into bytes
	//
	static bool unhex(const std::vector<char> &hex_chars, std::vector<char> &hex_bytes);

	//
	// Concatenate posix-style path1 and path2 up to max_len in size, normalizing the result.
	// path1 MUST be '/' terminated and is not sanitized.
	// If path2 is absolute, the result will be equivalent to path2.
	// If the result would be too long, the output will contain the string "/PATH_TOO_LONG" instead.
	//
	static std::string concatenate_paths(std::string_view path1, std::string_view path2);

	//
	// Determines if an IPv6 address is IPv4-mapped
	//
	static bool is_ipv4_mapped_ipv6(uint8_t* paddr);

	//
	// Given a string, scan the event list and find the longest argument that the input string contains
	//
	static const struct ppm_param_info* find_longest_matching_evt_param(std::string name);

	static uint64_t get_current_time_ns();

	static bool glob_match(const char *pattern, const char *string, const bool& case_insensitive = false);

#ifndef _WIN32
	//
	// Print the call stack
	//
	static void bt(void);
#endif // _WIN32

	static bool find_first_env(std::string &out, const std::vector<std::string> &env, const std::vector<std::string> &keys);
	static bool find_env(std::string &out, const std::vector<std::string> &env, const std::string &key);

	static void split_container_image(const std::string &image,
					  std::string &hostname,
					  std::string &port,
					  std::string &name,
					  std::string &tag,
					  std::string &digest,
					  bool split_repo = true);

	static void parse_suppressed_types(const std::vector<std::string>& supp_strs,
					   std::vector<ppm_event_code>* supp_ids);

	static const char* event_name_by_id(uint16_t id);

	static void ts_to_string(uint64_t ts, OUT std::string* res, bool date, bool ns);

	static void ts_to_iso_8601(uint64_t ts, OUT std::string* res);

        // Limited version of iso 8601 time string parsing, that assumes a
        // timezone of Z for UTC, but does support parsing fractional seconds,
        // unlike get_epoch_utc_seconds_* below.
	static bool parse_iso_8601_utc_string(const std::string& time_str, uint64_t &ns);

	//
	// Convert caps from their numeric representation to a space-separated string list
	//
	static std::string caps_to_string(const uint64_t caps);

	static uint64_t get_max_caps();
};

///////////////////////////////////////////////////////////////////////////////
// little STL thing to sanitize strings
///////////////////////////////////////////////////////////////////////////////

struct g_invalidchar
{
	bool operator()(char c) const
	{
		// Exclude all non-printable characters and control characters while
		// including a wide range of languages (emojis, cyrillic, chinese etc)
		return !(isprint((unsigned)c));
	}
};

inline void sanitize_string(std::string &str)
{
	// It turns out with -O3 (release flags) using erase and
	// remove_if is slightly faster than the inline version that
	// was here. It's not faster for -O2, and is actually much
	// slower without optimization.
	//
	// Optimize for the release case, then.
	str.erase(remove_if(str.begin(), str.end(), g_invalidchar()), str.end());
}

inline void remove_duplicate_path_separators(std::string &str)
{
    // Light fd name sanitization if fd is a file - only remove consecutive duplicate separators
    if(str.size() < 2)
    {
        // There is nothing to do if there are 0 or 1 chars in the string, protecting dereference operations
        return;
    }

    char prev_char = *str.begin();

    for (auto cur_char_it = str.begin() + 1; cur_char_it != str.end();)
    {
        if (prev_char == *cur_char_it && prev_char == '/')
        {
            cur_char_it = str.erase(cur_char_it);
        }
        else
        {
            prev_char = *cur_char_it;
            cur_char_it++;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Time utility functions.
///////////////////////////////////////////////////////////////////////////////

time_t get_epoch_utc_seconds(const std::string& time_str, const std::string& fmt = "%Y-%m-%dT%H:%M:%SZ");
time_t get_epoch_utc_seconds_now();

// Time functions for Windows

#ifdef _WIN32
struct timezone2
{
	int32_t  tz_minuteswest;
	bool  tz_dsttime;
};

SINSP_PUBLIC int gettimeofday(struct timeval *tv, struct timezone2 *tz);
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
std::string sinsp_gethostname();

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////

// each of these functions uses values in network byte order

std::string ipv4tuple_to_string(ipv4tuple* tuple, bool resolve);
std::string ipv6tuple_to_string(ipv6tuple* tuple, bool resolve);
std::string ipv4serveraddr_to_string(ipv4serverinfo* addr, bool resolve);
std::string ipv6serveraddr_to_string(ipv6serverinfo* addr, bool resolve);

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
std::vector<std::string> sinsp_split(const std::string& s, char delim);

template<typename It>
std::string sinsp_join(It begin, It end, char delim)
{
	if(begin == end)
	{
		return "";
	}
	std::stringstream ss;
	ss << *begin;
	++begin;
	for(auto it = begin; it != end; ++it)
	{
		ss << delim << *it;
	}
	return ss.str();
}

std::string& ltrim(std::string& s);
std::string& rtrim(std::string& s);
std::string& trim(std::string& s);
std::string& replace_in_place(std::string& s, const std::string& search, const std::string& replacement);
std::string replace(const std::string& str, const std::string& search, const std::string& replacement);

///////////////////////////////////////////////////////////////////////////////
// number parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_numparser
{
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
// JSON helpers
///////////////////////////////////////////////////////////////////////////////
namespace Json
{
	class Value;
}

std::string get_json_string(const Json::Value& obj, const std::string& name);
inline std::string json_as_string(const Json::Value& json)
{
	return Json::FastWriter().write(json);
}

///////////////////////////////////////////////////////////////////////////////
// A simple class to manage pre-allocated objects in a LIFO
// fashion and make sure all of them are deleted upon destruction.
///////////////////////////////////////////////////////////////////////////////
template<typename OBJ>
class simple_lifo_queue
{
public:
	simple_lifo_queue(uint32_t size)
	{
		uint32_t j;
		for(j = 0; j < size; j++)
		{
			OBJ* newentry = new OBJ;
			m_full_list.push_back(newentry);
			m_avail_list.push_back(newentry);
		}
	}
	~simple_lifo_queue()
	{
		while(!m_avail_list.empty())
		{
			OBJ* head = m_avail_list.front();
			delete head;
			m_avail_list.pop_front();
		}
	}

	void push(OBJ* newentry)
	{
		m_avail_list.push_front(newentry);
	}

	OBJ* pop()
	{
		if(m_avail_list.empty())
		{
			return NULL;
		}
		OBJ* head = m_avail_list.front();
		m_avail_list.pop_front();
		return head;
	}

	bool empty() const
	{
		return m_avail_list.empty();
	}

private:
	std::list<OBJ*> m_avail_list;
	std::list<OBJ*> m_full_list;
};

///////////////////////////////////////////////////////////////////////////////
// Case-insensitive string find.
///////////////////////////////////////////////////////////////////////////////
template<typename charT>
struct ci_equal
{
	ci_equal(const std::locale& loc) : m_loc(loc) {}
	bool operator()(charT ch1, charT ch2)
	{
		return std::toupper(ch1, m_loc) == std::toupper(ch2, m_loc);
	}
private:
	const std::locale& m_loc;
};

template<typename T>
int ci_find_substr(const T& str1, const T& str2, const std::locale& loc = std::locale())
{
	auto it = std::search(str1.begin(), str1.end(),
		str2.begin(), str2.end(), ci_equal<typename T::value_type>(loc) );
	if(it != str1.end()) { return it - str1.begin(); }
	return -1;
}

struct ci_compare
{
	// less-than, for use in STL containers
	bool operator() (const std::string& a, const std::string& b) const
	{
		return strcasecmp(a.c_str(), b.c_str()) < 0;
	}

	static bool is_equal(const std::string& a, const std::string& b)
	{
		return strcasecmp(a.c_str(), b.c_str()) == 0;
	}
};

///////////////////////////////////////////////////////////////////////////////
// socket helpers
///////////////////////////////////////////////////////////////////////////////

bool set_socket_blocking(int sock, bool block);

unsigned int read_num_possible_cpus(void);

///////////////////////////////////////////////////////////////////////////////
// hashing helpers
///////////////////////////////////////////////////////////////////////////////

// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n3876.pdf
template <typename T>
inline void hash_combine(std::size_t &seed, const T& val)
{
	seed ^= std::hash<T>()(val) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}

///////////////////////////////////////////////////////////////////////////////
// Log helpers
///////////////////////////////////////////////////////////////////////////////
void sinsp_scap_log_fn(const char* component, const char* msg, const enum falcosecurity_log_severity sev);

///////////////////////////////////////////////////////////////////////////////
// Set operation functions.
///////////////////////////////////////////////////////////////////////////////


template<typename T>
std::set<T> unordered_set_to_ordered(const std::unordered_set<T>& unordered_set);

template<typename T>
std::unordered_set<T> unordered_set_difference(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_difference(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_union(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_union(const std::set<T>& a, const std::set<T>& b);

template<typename T>
std::unordered_set<T> unordered_set_intersection(const std::unordered_set<T>& a, const std::unordered_set<T>& b);

template<typename T>
std::set<T> set_intersection(const std::set<T>& a, const std::set<T>& b);

std::string concat_set_in_order(const std::unordered_set<std::string>& s, const std::string& delim = ", ");
std::string concat_set_in_order(const std::set<std::string>& s, const std::string& delim = ", ");
