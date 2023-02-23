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

#pragma once

#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <netinet/in.h>

#define ASSERT_NAMES_EQ(a, b) { \
	ASSERT_EQ(std::set<std::string>(a.begin(), a.end()), std::set<std::string>(b.begin(), b.end())); \
	ASSERT_EQ(a.size(), b.size()); \
}

#define ASSERT_PPM_EVENT_CODES_EQ(a, b) { \
	ASSERT_EQ(libsinsp::events::set<ppm_event_code>(a.begin(), a.end()), libsinsp::events::set<ppm_event_code>(b.begin(), b.end())); \
	ASSERT_TRUE(a.equals(b)); \
	ASSERT_EQ(a.size(), b.size()); \
}

#define ASSERT_PPM_SC_CODES_EQ(a, b) { \
	ASSERT_EQ(libsinsp::events::set<ppm_sc_code>(a.begin(), a.end()), libsinsp::events::set<ppm_sc_code>(b.begin(), b.end())); \
	ASSERT_TRUE(a.equals(b)); \
	ASSERT_EQ(a.size(), b.size()); \
}

namespace test_utils {

// transform a list of strings into a single string where each element is delimited by a null (0) byte.
// the last element will also be null-terminated unless the input list is empty.
std::string to_null_delimited(std::vector<std::string> list);

// This helper is used to convert an unordered set into an ordered set.
template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set);

std::vector<uint8_t> pack_sockaddr(sockaddr *sa);
std::vector<uint8_t> pack_socktuple(sockaddr *src, sockaddr *dest);

void print_bytes(uint8_t *buf, size_t size);

std::string describe_string(const char* nullable_string);

} // namespace test_utils
