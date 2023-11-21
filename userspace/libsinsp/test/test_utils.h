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

#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#if !defined(_WIN32)
#include <netinet/in.h>
#endif //_WIN32
#include <driver/event_stats.h>

#define ASSERT_NAMES_EQ(a, b)                                                                                \
	{                                                                                                        \
		auto a1 = a;                                                                                         \
		auto b1 = b;                                                                                         \
		EXPECT_EQ(a1.size(), b1.size());                                                                     \
		ASSERT_EQ(std::set<std::string>(a1.begin(), a1.end()), std::set<std::string>(b1.begin(), b1.end())); \
	}

// `merge` requires cpp17...
#define ASSERT_CONTAINS(a, b)            \
	{                                    \
		auto a1 = a;                     \
		auto b1 = b;                     \
		uint32_t prev_size = a1.size();  \
		for(const auto& val : b1)        \
		{                                \
			a1.insert(val);              \
		}                                \
		ASSERT_EQ(prev_size, a1.size()); \
	}

// `merge` requires cpp17...
#define ASSERT_NOT_CONTAINS(a, b)                    \
	{                                                \
		auto a1 = a;                                 \
		auto b1 = b;                                 \
		uint32_t prev_size = a1.size();              \
		for(const auto& val : b1)                    \
		{                                            \
			a1.insert(val);                          \
		}                                            \
		ASSERT_EQ(prev_size + b1.size(), a1.size()); \
	}

#define ASSERT_PPM_EVENT_CODES_EQ(a, b)                                                                                                              \
	{                                                                                                                                            \
		auto a1 = a;                                                                                                                         \
		auto b1 = b;                                                                                                                         \
		EXPECT_EQ(a1.size(), b1.size());                                                                                               \
		ASSERT_EQ(libsinsp::events::set<ppm_event_code>(a1.begin(), a1.end()), libsinsp::events::set<ppm_event_code>(b1.begin(), b1.end())); \
		ASSERT_TRUE(a1.equals(b1));                                                                                                          \
	}

#define ASSERT_PPM_SC_CODES_EQ(a, b)                                                                                                           \
	{                                                                                                                                      \
		auto a1 = a;                                                                                                                   \
		auto b1 = b;                                                                                                                   \
		EXPECT_EQ(a1.size(), b1.size());                                                                                               \
		ASSERT_EQ(libsinsp::events::set<ppm_sc_code>(a1.begin(), a1.end()), libsinsp::events::set<ppm_sc_code>(b1.begin(), b1.end())); \
		ASSERT_TRUE(a1.equals(b1));                                                                                                    \
	}

namespace test_utils {

// transform a list of strings into a single string where each element is delimited by a null (0) byte.
// the last element will also be null-terminated unless the input list is empty.
std::string to_null_delimited(std::vector<std::string> list);

// This helper is used to convert an unordered set into an ordered set.
template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set);

#if !defined(_WIN32)
struct sockaddr_in fill_sockaddr_in(int32_t ipv4_port, const char* ipv4_string);
struct sockaddr_in6 fill_sockaddr_in6(int32_t ipv6_port, const char* ipv6_string);
std::vector<uint8_t> pack_sockaddr(sockaddr *sa);
std::vector<uint8_t> pack_socktuple(sockaddr *src, sockaddr *dest);
#endif //_WIN32

void print_bytes(uint8_t *buf, size_t size);

std::string describe_string(const char* nullable_string);

} // namespace test_utils
