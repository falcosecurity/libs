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

#include "test_utils.h"

#include <cstring>

#if defined(__linux__)
#include <linux/un.h>
#else
#if !defined(_WIN32)
#include <sys/un.h>
# endif //_WIN32
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
#endif

#if !defined(_WIN32)
#include <arpa/inet.h>
#endif //_WIN32
#include <stdint.h>

#include <driver/ppm_events_public.h>
#include <libscap/userspace_flag_helpers.h>

namespace test_utils {

#if !defined(_WIN32)
sockaddr_in fill_sockaddr_in(int32_t ipv4_port, const char* ipv4_string)
{
	sockaddr_in sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(ipv4_port);
	inet_pton(AF_INET, ipv4_string, &(sockaddr.sin_addr));
	return sockaddr;
}

sockaddr_in6 fill_sockaddr_in6(int32_t ipv6_port, const char* ipv6_string)
{
	sockaddr_in6 sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_port = htons(ipv6_port);
	inet_pton(AF_INET6, ipv6_string, &(sockaddr.sin6_addr));
	return sockaddr;
}
#endif //_WIN32

std::string to_null_delimited(const std::vector<std::string> list)
{
	std::string res;

	for (std::string item : list) {
		res += item;
		res.push_back('\0');
	}

	return res;
}

template<typename T>
std::set<T> unordered_set_to_ordered(std::unordered_set<T> unordered_set)
{
	std::set<T> s;
	for(const auto& val : unordered_set)
	{
		s.insert(val);
	}
	return s;
}
template std::set<uint32_t> unordered_set_to_ordered(std::unordered_set<uint32_t> unordered_set);
template std::set<std::string> unordered_set_to_ordered(std::unordered_set<std::string> unordered_set);

void print_bytes(uint8_t *buf, size_t size)
{
	for(size_t i = 0; i < size; i++)
	{
		if (i % 16 == 0) {
			printf("%03lx | ", i);
		}
		printf("%02x ", buf[i]);
		if (i % 16 == 0xf) {
			printf("\n");
		}
	}
	printf("\n");
}

std::string describe_string(const char* nullable_string)
{
	std::string description;
	if (nullable_string == nullptr) {
		description.append("literal NULL");
	} else {
		description.append("\"");
		description.append(nullable_string);
		description.append("\"");
	}

	return description;
}

inline void vecbuf_append(std::vector<uint8_t> &dest, void* src, size_t size)
{
	uint8_t *src_bytes = reinterpret_cast<uint8_t*>(src);
	for (size_t i = 0; i < size; i++) {
		uint8_t byte;
		memcpy(&byte, src_bytes + i, 1);
		dest.push_back(byte);
	}
}

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
std::vector<uint8_t> pack_addr(sockaddr *sa)
{
	std::vector<uint8_t> res;
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in *)sa;
			vecbuf_append(res, &sa_in->sin_addr.s_addr, sizeof(sa_in->sin_addr.s_addr));
		}
		break;

		case AF_INET6:
		{
			sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
			vecbuf_append(res, &sa_in6->sin6_addr, 2 * sizeof(uint64_t));
		}
		break;

		case AF_UNIX:
		{
			sockaddr_un *sa_un = (sockaddr_un *)sa;
			std::string path = std::string(sa_un->sun_path);
			path = path.substr(0, UNIX_PATH_MAX);
			path.push_back('\0');
			res.insert(res.end(), path.begin(), path.end());
		}
		break;
	}

	return res;
}

uint16_t get_port(sockaddr *sa)
{
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in *)sa;
			return ntohs(sa_in->sin_port);
		}
		break;

		case AF_INET6:
		{
			sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
			return ntohs(sa_in6->sin6_port);
		}
		break;

	}

	return 0;
}

std::vector<uint8_t> pack_addr_port(sockaddr *sa)
{
	std::vector<uint8_t> res;
	uint16_t dport = get_port(sa);
	switch(sa->sa_family)
	{
		case AF_INET:
		case AF_INET6:
		{
			auto addr = pack_addr(sa);
			res.insert(res.end(), addr.begin(), addr.end());
			vecbuf_append(res, &dport, sizeof(uint16_t));
		}
		break;

		case AF_UNIX:
		{
			return pack_addr(sa);
		}
		break;
	}

	return res;
}

uint8_t get_sock_family(sockaddr *sa)
{
	uint8_t sock_family = 0;
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in *)sa;
			sock_family = socket_family_to_scap(sa_in->sin_family);
		}
		break;

		case AF_INET6:
		{
			sockaddr_in6 *sa_in6 = (sockaddr_in6 *)sa;
			sock_family = socket_family_to_scap(sa_in6->sin6_family);
		}
		break;

		case AF_UNIX:
		{
			sockaddr_un *sa_un = (sockaddr_un *)sa;
			sock_family = socket_family_to_scap(sa_un->sun_family);
		}
		break;
	}

	return sock_family;
}

std::vector<uint8_t> pack_sockaddr(sockaddr *sa)
{
	std::vector<uint8_t> res;
	res.push_back(get_sock_family(sa));
	auto addr_port = pack_addr_port(sa);
	res.insert(res.end(), addr_port.begin(), addr_port.end());

	return res;
}

std::vector<uint8_t> pack_socktuple(sockaddr *src, sockaddr *dest)
{
	std::vector<uint8_t> res;

	res.push_back(get_sock_family(src));
	auto src_addr = pack_addr_port(src);
	auto dest_addr = pack_addr_port(dest);

	res.insert(res.end(), src_addr.begin(), src_addr.end());
	res.insert(res.end(), dest_addr.begin(), dest_addr.end());

	return res;
}
#endif //_WIN32 __EMSCRIPTEN__

} // namespace test_utils
