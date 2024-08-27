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

#include <libsinsp/tuples.h>
#include <string>
#include <cstring>
#include <libsinsp/sinsp_inet.h>
#include <libsinsp/utils.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/logger.h>

// ensure proper memory layout for ipv6addr class during compile time
static_assert(sizeof(ipv6addr) == 16);

// is_pod check split into is_standard_layout && is_trivial to be C++20 future proof
static_assert(std::is_standard_layout<ipv6addr>::value && std::is_trivial<ipv6addr>::value);

ipv6addr ipv6addr::empty_address ("0::");//= {0x00000000, 0x00000000, 0x00000000, 0x00000000};

ipv6addr::ipv6addr(const std::string &str_addr)
{
	if(inet_pton(AF_INET6, str_addr.c_str(), m_b) != 1)
	{
		throw sinsp_exception("unrecognized IPv6 address " + str_addr);
	}
}

bool ipv6addr::operator==(const ipv6addr &other) const
{
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1] &&
		m_b[2] == other.m_b[2] &&
		m_b[3] == other.m_b[3]);
}

bool ipv6addr::operator!=(const ipv6addr &other) const
{
	return !operator==(other);
}

bool ipv6addr::operator<(const ipv6addr &other) const
{
	for(int i = 0; i < 4; i++)
	{
		if(m_b[i] < other.m_b[i]) return true;
		else if(other.m_b[i] < m_b[i]) return false;
	}
	return false;
}

bool ipv6addr::in_subnet(const ipv6addr &other) const
{
	// They're in the same subnet if the first 64 bits match
	// (Assumes convention of first 48 bits for network, next 16
	// bits for subnet).
	return (m_b[0] == other.m_b[0] &&
		m_b[1] == other.m_b[1]);
}

void ipv6net::init(const std::string &str)
{
	std::stringstream ss(str);
	std::string ip, mask;

	getline(ss, ip, '/');
	getline(ss, mask);

	if(inet_pton(AF_INET6, ip.c_str(), m_addr.m_b) != 1)
	{
		throw sinsp_exception("unrecognized IPv6 address " + std::string(str));
	}

	uint32_t prefix_len = sinsp_numparser::parseu8(mask);

	if (prefix_len == 0 || prefix_len > 128)
	{
		throw sinsp_exception("invalid v6 netmask " + mask);
	}

	m_mask_len_bytes = prefix_len / 8;
	m_mask_tail_bits = 8 - (prefix_len % 8);

	if (m_mask_tail_bits == 8)
	{
		--m_mask_len_bytes;
		m_mask_tail_bits = 0;
	}
}

ipv6net::ipv6net(const std::string &str)
{
	if(strchr(str.c_str(), '/') != nullptr)
	{
		init(str);
	}
	else
	{
		throw sinsp_exception("invalid v6 netmask: " + str);
	}
}

bool ipv6net::in_cidr(const ipv6addr &other) const
{
	auto this_bytes  = (const uint8_t*)(&m_addr.m_b);
	auto other_bytes = (const uint8_t*)(&other.m_b);

	unsigned int i = 0;
	for (; i < m_mask_len_bytes; i++)
	{
		if(this_bytes[i] != other_bytes[i])
		{
			return false;
		}
	}
	return (this_bytes[i] >> m_mask_tail_bits) == (other_bytes[i] >> m_mask_tail_bits);
}
