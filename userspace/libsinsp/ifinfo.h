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

#include <libsinsp/settings.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/tuples.h>
#include <libsinsp/fdinfo.h>

#include <string>
#include <vector>

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

typedef struct scap_addrlist scap_addrlist;
typedef struct scap_ifinfo_ipv4 scap_ifinfo_ipv4;
typedef struct scap_ifinfo_ipv6 scap_ifinfo_ipv6;
class sinsp_threadinfo;

//
// network interface info ipv4
//
class SINSP_PUBLIC sinsp_ipv4_ifinfo
{
public:
	sinsp_ipv4_ifinfo() = default;
	sinsp_ipv4_ifinfo(uint32_t addr, uint32_t netmask, uint32_t bcast, const char* name);

	std::string to_string() const;
	std::string address() const;

	uint32_t m_addr;
	uint32_t m_netmask;
	uint32_t m_bcast;
	std::string m_name;

private:
	static void convert_to_string(char * dest, size_t len, const uint32_t addr);
};

//
// network interface info ipv6
//
class SINSP_PUBLIC sinsp_ipv6_ifinfo
{
public:
	sinsp_ipv6_ifinfo() = default;

	ipv6addr m_net;

	std::string m_name;
};

class SINSP_PUBLIC sinsp_network_interfaces
{
public:
	sinsp_network_interfaces();

	void import_interfaces(scap_addrlist* paddrlist);
	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);
	void update_fd(sinsp_fdinfo& fd);
	bool is_ipv4addr_in_subnet(uint32_t addr) const;
	bool is_ipv4addr_in_local_machine(uint32_t addr, sinsp_threadinfo* tinfo) const;
	void import_ipv6_interface(const sinsp_ipv6_ifinfo& ifinfo);
	bool is_ipv6addr_in_local_machine(ipv6addr &addr, sinsp_threadinfo* tinfo) const;
	std::vector<sinsp_ipv4_ifinfo>* get_ipv4_list();
	std::vector<sinsp_ipv6_ifinfo>* get_ipv6_list();
	inline void clear();

	ipv6addr m_ipv6_loopback_addr;

VISIBILITY_PRIVATE
	uint32_t infer_ipv4_address(uint32_t destination_address);
	void import_ipv4_ifaddr_list(uint32_t count, scap_ifinfo_ipv4* plist);
	ipv6addr infer_ipv6_address(ipv6addr &destination_address);
	void import_ipv6_ifaddr_list(uint32_t count, scap_ifinfo_ipv6* plist);
	std::vector<sinsp_ipv4_ifinfo> m_ipv4_interfaces;
	std::vector<sinsp_ipv6_ifinfo> m_ipv6_interfaces;
};

void sinsp_network_interfaces::clear()
{
	m_ipv4_interfaces.clear();
	m_ipv6_interfaces.clear();
}
