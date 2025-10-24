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

#include <libsinsp/sinsp_int.h>

sinsp_network_interfaces::sinsp_network_interfaces(): m_ipv6_loopback_addr{} {
	if(inet_pton(AF_INET6, "::1", m_ipv6_loopback_addr.m_b) != 1) {
		throw sinsp_exception("Could not convert ipv6 loopback address ::1 to ipv6addr struct");
	}
}

sinsp_ipv4_ifinfo::sinsp_ipv4_ifinfo(const uint32_t addr,
                                     const uint32_t netmask,
                                     const uint32_t bcast,
                                     const char* name) {
	m_addr = addr;
	m_netmask = netmask;
	m_bcast = bcast;
	m_name = name;
}

void sinsp_ipv4_ifinfo::convert_to_string(char* dest, size_t len, const uint32_t addr) {
	const uint32_t addr_network_byte_order = htonl(addr);
	snprintf(dest,
	         len,
	         "%d.%d.%d.%d",
	         ((addr_network_byte_order & 0xFF000000) >> 24),
	         ((addr_network_byte_order & 0xFF0000) >> 16),
	         ((addr_network_byte_order & 0xFF00) >> 8),
	         (addr_network_byte_order & 0xFF));
}

std::string sinsp_ipv4_ifinfo::address() const {
	char str_addr[16];
	convert_to_string(str_addr, sizeof(str_addr), m_addr);
	return std::string(str_addr);
}

std::string sinsp_ipv4_ifinfo::to_string() const {
	char s[100];
	char str_addr[16];
	char s_netmask[16];
	char s_bcast[16];

	convert_to_string(str_addr, sizeof(str_addr), m_addr);
	convert_to_string(s_netmask, sizeof(str_addr), m_netmask);
	convert_to_string(s_bcast, sizeof(str_addr), m_bcast);
	snprintf(s,
	         sizeof(s),
	         "%s inet %s netmask %s broadcast %s",
	         m_name.c_str(),
	         str_addr,
	         s_netmask,
	         s_bcast);
	return std::string(s);
}

std::string sinsp_ipv4_ifinfo::addr_to_string(const uint32_t addr) {
	char str_addr[16];
	convert_to_string(str_addr, sizeof(str_addr), addr);
	return std::string(str_addr);
}

std::string sinsp_ipv4_ifinfo::addr_to_string() const {
	char str_addr[16];
	convert_to_string(str_addr, sizeof(str_addr), m_addr);
	return std::string(str_addr);
}

std::string sinsp_ipv6_ifinfo::addr_to_string() const {
	std::ostringstream oss;
	const uint16_t* words = reinterpret_cast<const uint16_t*>(m_net.m_b);
	for(int i = 0; i < 8; ++i) {
		if(i != 0) {
			oss << ':';
		}
		oss << std::hex << ntohs(words[i]);
	}
	return oss.str();
}

uint32_t sinsp_network_interfaces::infer_ipv4_address(const uint32_t destination_address) const {
	std::vector<sinsp_ipv4_ifinfo>::const_iterator it;

	// first try to find exact match
	for(it = m_ipv4_interfaces.cbegin(); it != m_ipv4_interfaces.cend(); ++it) {
		if(it->m_addr == destination_address) {
			return it->m_addr;
		}
	}

	// try to find an interface for the same subnet
	for(it = m_ipv4_interfaces.cbegin(); it != m_ipv4_interfaces.cend(); ++it) {
		if((it->m_addr & it->m_netmask) == (destination_address & it->m_netmask)) {
			return it->m_addr;
		}
	}

	// otherwise take the first non loopback interface
	for(it = m_ipv4_interfaces.cbegin(); it != m_ipv4_interfaces.cend(); ++it) {
		if(it->m_addr != ntohl(INADDR_LOOPBACK)) {
			return it->m_addr;
		}
	}
	return 0;
}

void sinsp_network_interfaces::update_fd(sinsp_fdinfo& fd) const {
	ipv4tuple* pipv4info = &fd.m_sockinfo.m_ipv4info;
	ipv6tuple* pipv6info = &fd.m_sockinfo.m_ipv6info;

	// Only handle ipv4/ipv6 sockets.
	if(fd.m_type != SCAP_FD_IPV4_SOCK && fd.m_type != SCAP_FD_IPV6_SOCK) {
		return;
	}

	// Handle IPv4 sockets.
	if(fd.m_type == SCAP_FD_IPV4_SOCK) {
		if(pipv4info->m_fields.m_sip != 0 && pipv4info->m_fields.m_dip != 0) {
			return;
		}

		if(pipv4info->m_fields.m_sip == 0) {
			const uint32_t newaddr = infer_ipv4_address(pipv4info->m_fields.m_dip);
			if(newaddr == pipv4info->m_fields.m_dip &&
			   pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport) {
				return;
			}

			pipv4info->m_fields.m_sip = newaddr;
		} else {
			const uint32_t newaddr = infer_ipv4_address(pipv4info->m_fields.m_sip);
			if(newaddr == pipv4info->m_fields.m_sip &&
			   pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport) {
				return;
			}

			pipv4info->m_fields.m_dip = newaddr;
		}
		return;
	}

	// Handle IPv6 sockets.
	if(pipv6info->m_fields.m_sip != ipv6addr::empty_address &&
	   pipv6info->m_fields.m_dip != ipv6addr::empty_address) {
		return;
	}

	if(pipv6info->m_fields.m_sip == ipv6addr::empty_address) {
		const ipv6addr newaddr = infer_ipv6_address(pipv6info->m_fields.m_dip);
		if(newaddr == pipv6info->m_fields.m_dip &&
		   pipv6info->m_fields.m_sport == pipv6info->m_fields.m_dport) {
			return;
		}

		pipv6info->m_fields.m_sip = newaddr;
		return;
	}

	const ipv6addr newaddr = infer_ipv6_address(pipv6info->m_fields.m_sip);
	if(newaddr == pipv6info->m_fields.m_sip &&
	   pipv6info->m_fields.m_sport == pipv6info->m_fields.m_dport) {
		return;
	}

	pipv6info->m_fields.m_dip = newaddr;
}

bool sinsp_network_interfaces::is_ipv4addr_in_subnet(const uint32_t addr) const {
	//
	// Accept everything that comes from private internets:
	// - 10.0.0.0/8
	// - 192.168.0.0/16
	// - 172.16.0.0/12
	//
	const uint32_t addr_network_byte_order = htonl(addr);
	if((addr_network_byte_order & 0xff000000) == 0x0a000000 ||
	   (addr_network_byte_order & 0xffff0000) == 0xc0a80000 ||
	   (addr_network_byte_order & 0xff3f0000) == 0xac100000) {
		return true;
	}

	// try to find an interface for the same subnet
	for(auto& el : m_ipv4_interfaces) {
		if((el.m_addr & el.m_netmask) == (addr & el.m_netmask)) {
			return true;
		}
	}

	return false;
}

bool sinsp_network_interfaces::is_ipv4addr_in_local_machine(const uint32_t addr,
                                                            ::plugin_tables& plugin_tables,
                                                            sinsp_threadinfo* tinfo) const {
	if(!plugin_tables.get_container_id(*tinfo).empty()) {
		const auto ip = plugin_tables.get_container_ip(*tinfo);
		if(!ip.empty()) {
			struct in_addr in;
			if(inet_pton(AF_INET, ip.c_str(), &in)) {
				if(addr == in.s_addr) {
					return true;
				}
			}
		} else {
			bool found = false;
			plugin_tables.foreach_container_ip([&](const std::string& ip) {
				struct in_addr in;
				if(!ip.empty() && inet_pton(AF_INET, ip.c_str(), &in)) {
					if(addr == in.s_addr) {
						found = true;
						return false;  // break-out loop
					}
				}
				return true;
			});
			return found;
		}
	}

	// try to find an interface that has the given IP as address
	for(const auto& ipv4interface : m_ipv4_interfaces) {
		if(ipv4interface.m_addr == addr) {
			return true;
		}
	}

	return false;
}

void sinsp_network_interfaces::import_ipv4_ifaddr_list(const uint32_t count,
                                                       const scap_ifinfo_ipv4* plist) {
	if(count == 0) {
		return;
	}
	for(uint32_t j = 0; j < count; j++) {
		sinsp_ipv4_ifinfo info;
		info.m_addr = plist->addr;
		info.m_netmask = plist->netmask;
		info.m_bcast = plist->bcast;
		info.m_name = plist->ifname;
		m_ipv4_interfaces.push_back(info);
		plist++;
	}
}

ipv6addr sinsp_network_interfaces::infer_ipv6_address(const ipv6addr& destination_address) const {
	std::vector<sinsp_ipv6_ifinfo>::const_iterator it;

	// first try to find exact match
	for(it = m_ipv6_interfaces.cbegin(); it != m_ipv6_interfaces.cend(); ++it) {
		if(destination_address == it->m_net) {
			return it->m_net;
		}
	}

	// try to find an interface for the same subnet
	for(it = m_ipv6_interfaces.cbegin(); it != m_ipv6_interfaces.cend(); ++it) {
		if(it->m_net.in_subnet(destination_address)) {
			return it->m_net;
		}
	}

	// otherwise take the first non loopback interface
	for(it = m_ipv6_interfaces.cbegin(); it != m_ipv6_interfaces.cend(); ++it) {
		if(it->m_net != m_ipv6_loopback_addr) {
			return it->m_net;
		}
	}

	return ipv6addr::empty_address;
}

bool sinsp_network_interfaces::is_ipv6addr_in_local_machine(const ipv6addr& addr,
                                                            const plugin_tables& plugin_tables,
                                                            sinsp_threadinfo* tinfo) const {
	if(!plugin_tables.get_container_id(*tinfo).empty()) {
		// For now, not supporting ipv6 networking for containers. So always return false;
		return false;
	}

	// try to find an interface that has the given IP as address
	for(const auto& ipv6interface : m_ipv6_interfaces) {
		if(addr.in_subnet(ipv6interface.m_net)) {
			return true;
		}
	}

	return false;
}

void sinsp_network_interfaces::import_ipv6_ifaddr_list(const uint32_t count,
                                                       const scap_ifinfo_ipv6* plist) {
	if(count == 0) {
		return;
	}
	for(uint32_t j = 0; j < count; j++) {
		sinsp_ipv6_ifinfo info;

		// Only saving the address portion. (Assumes
		// convention of first 48 bits for network, next 16
		// bits for subnet).
		memcpy(info.m_net.m_b, plist->addr, SCAP_IPV6_ADDR_LEN);

		info.m_name = plist->ifname;
		m_ipv6_interfaces.push_back(info);
		plist++;
	}
}

void sinsp_network_interfaces::import_interfaces(const scap_addrlist* paddrlist) {
	if(paddrlist != nullptr) {
		clear();
		import_ipv4_ifaddr_list(paddrlist->n_v4_addrs, paddrlist->v4list);
		import_ipv6_ifaddr_list(paddrlist->n_v6_addrs, paddrlist->v6list);
	}
}

void sinsp_network_interfaces::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo) {
	m_ipv4_interfaces.push_back(ifinfo);
}

void sinsp_network_interfaces::import_ipv6_interface(const sinsp_ipv6_ifinfo& ifinfo) {
	m_ipv6_interfaces.push_back(ifinfo);
}

std::vector<sinsp_ipv4_ifinfo>* sinsp_network_interfaces::get_ipv4_list() {
	return &m_ipv4_interfaces;
}

std::vector<sinsp_ipv6_ifinfo>* sinsp_network_interfaces::get_ipv6_list() {
	return &m_ipv6_interfaces;
}
