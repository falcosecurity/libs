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

#ifndef _WIN32
#include <inttypes.h>
#include <algorithm>
#endif
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>

template<auto Member, size_t Offset>
struct ipv6_client_field {
	static_assert(Offset == 0 || Offset == 2,
	              "Offset must be either 0 (for low bits) or 2 (for high bits)");

	static constexpr ss_plugin_state_type type_id() { return SS_PLUGIN_ST_UINT64; }

	static uint64_t read(const sinsp_fdinfo* c) {
		uint64_t addr;
		const ipv6addr& a = (c->m_sockinfo.m_ipv6info.m_fields.*Member);
		memcpy(&addr, &a.m_b[Offset], sizeof(uint64_t));
		return addr;
	}

	static void write(sinsp_fdinfo* c, const libsinsp::state::borrowed_state_data& in_data) {
		ipv6addr& a = (c->m_sockinfo.m_ipv6info.m_fields.*Member);
		memcpy(&a.m_b[Offset], &in_data.data().u64, sizeof(uint64_t));
	}
};

template<size_t Offset>
struct ipv6_server_field {
	static_assert(Offset == 0 || Offset == 2,
	              "Offset must be either 0 (for low bits) or 2 (for high bits)");

	static constexpr ss_plugin_state_type type_id() { return SS_PLUGIN_ST_UINT64; }

	static uint64_t read(const sinsp_fdinfo* c) {
		uint64_t addr;
		const ipv6addr& a = (c->m_sockinfo.m_ipv6serverinfo.m_ip);
		memcpy(&addr, &a.m_b[Offset], sizeof(uint64_t));
		return addr;
	}

	static void write(sinsp_fdinfo* c, const libsinsp::state::borrowed_state_data& in_data) {
		ipv6addr& a = (c->m_sockinfo.m_ipv6serverinfo.m_ip);
		memcpy(&a.m_b[Offset], &in_data.data().u64, sizeof(uint64_t));
	}
};

struct fd_type {
	static constexpr ss_plugin_state_type type_id() { return SS_PLUGIN_ST_UINT8; }

	static uint8_t read(const sinsp_fdinfo* c) { return c->m_type; }
	static void write(sinsp_fdinfo* c, const libsinsp::state::borrowed_state_data& in_data) {
		c->m_type = static_cast<scap_fd_type>(in_data.data().u8);
	}
};

char sinsp_fdinfo::get_typechar() const {
	switch(m_type) {
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
		return CHAR_FD_FILE;
	case SCAP_FD_IPV4_SOCK:
		return CHAR_FD_IPV4_SOCK;
	case SCAP_FD_IPV6_SOCK:
		return CHAR_FD_IPV6_SOCK;
	case SCAP_FD_DIRECTORY:
		return CHAR_FD_DIRECTORY;
	case SCAP_FD_IPV4_SERVSOCK:
		return CHAR_FD_IPV4_SERVSOCK;
	case SCAP_FD_IPV6_SERVSOCK:
		return CHAR_FD_IPV6_SERVSOCK;
	case SCAP_FD_FIFO:
		return CHAR_FD_FIFO;
	case SCAP_FD_UNIX_SOCK:
		return CHAR_FD_UNIX_SOCK;
	case SCAP_FD_EVENT:
		return CHAR_FD_EVENT;
	case SCAP_FD_UNKNOWN:
		return CHAR_FD_UNKNOWN;
	case SCAP_FD_UNSUPPORTED:
		return CHAR_FD_UNSUPPORTED;
	case SCAP_FD_SIGNALFD:
		return CHAR_FD_SIGNAL;
	case SCAP_FD_EVENTPOLL:
		return CHAR_FD_EVENTPOLL;
	case SCAP_FD_INOTIFY:
		return CHAR_FD_INOTIFY;
	case SCAP_FD_TIMERFD:
		return CHAR_FD_TIMERFD;
	case SCAP_FD_NETLINK:
		return CHAR_FD_NETLINK;
	case SCAP_FD_BPF:
		return CHAR_FD_BPF;
	case SCAP_FD_USERFAULTFD:
		return CHAR_FD_USERFAULTFD;
	case SCAP_FD_IOURING:
		return CHAR_FD_IO_URING;
	case SCAP_FD_MEMFD:
		return CHAR_FD_MEMFD;
	case SCAP_FD_PIDFD:
		return CHAR_FD_PIDFD;
	default:
		//		ASSERT(false);
		return '?';
	}
}

const char* sinsp_fdinfo::get_typestring() const {
	switch(m_type) {
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
		return "file";
	case SCAP_FD_DIRECTORY:
		return "directory";
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
		return "ipv4";
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		return "ipv6";
	case SCAP_FD_UNIX_SOCK:
		return "unix";
	case SCAP_FD_FIFO:
		return "pipe";
	case SCAP_FD_EVENT:
		return "event";
	case SCAP_FD_SIGNALFD:
		return "signalfd";
	case SCAP_FD_EVENTPOLL:
		return "eventpoll";
	case SCAP_FD_INOTIFY:
		return "inotify";
	case SCAP_FD_TIMERFD:
		return "timerfd";
	case SCAP_FD_NETLINK:
		return "netlink";
	case SCAP_FD_BPF:
		return "bpf";
	case SCAP_FD_USERFAULTFD:
		return "userfaultfd";
	case SCAP_FD_IOURING:
		return "io_uring";
	case SCAP_FD_MEMFD:
		return "memfd";
	case SCAP_FD_PIDFD:
		return "pidfd";
	default:
		return "<NA>";
	}
}

sinsp_fdinfo::sinsp_fdinfo(const std::shared_ptr<libsinsp::state::dynamic_field_infos>& dyn_fields):
        extensible_struct(dyn_fields) {}

libsinsp::state::static_field_infos sinsp_fdinfo::get_static_fields() {
	using self = sinsp_fdinfo;
	using namespace libsinsp::state;

	static_field_infos ret;

	define_custom_static_field<fd_type>(ret, "type");

	// the rest fo the fields are more trivial to expose
	define_static_member_field<&self::m_openflags>(ret, "open_flags");
	define_static_member_field<&self::m_name>(ret, "name");
	define_static_member_field<&self::m_name_raw>(ret, "name_raw");
	define_static_member_field<&self::m_oldname>(ret, "old_name");
	define_static_member_field<&self::m_flags>(ret, "flags");
	define_static_member_field<&self::m_dev>(ret, "dev");
	define_static_member_field<&self::m_mount_id>(ret, "mount_id");
	define_static_member_field<&self::m_ino>(ret, "ino");
	define_static_member_field<&self::m_pid>(ret, "pid");
	define_static_member_field<&self::m_fd>(ret, "fd");

	// in this case we have a union, so many of the following exposed fields
	// will point to the same memory areas, but this should not be an issue
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4info,
	                           &ipv4tuple::m_fields,
	                           &decltype(ipv4tuple::m_fields)::m_sip>(ret, "socket_ipv4_src_ip");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4info,
	                           &ipv4tuple::m_fields,
	                           &decltype(ipv4tuple::m_fields)::m_dip>(ret, "socket_ipv4_dest_dip");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4info,
	                           &ipv4tuple::m_fields,
	                           &decltype(ipv4tuple::m_fields)::m_sport>(ret,
	                                                                    "socket_ipv4_src_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4info,
	                           &ipv4tuple::m_fields,
	                           &decltype(ipv4tuple::m_fields)::m_dport>(ret,
	                                                                    "socket_ipv4_dst_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4info,
	                           &ipv4tuple::m_fields,
	                           &decltype(ipv4tuple::m_fields)::m_l4proto>(ret,
	                                                                      "socket_ipv4_l4_proto");

	define_custom_static_field<ipv6_client_field<&decltype(ipv6tuple::m_fields)::m_sip, 0>>(
	        ret,
	        "socket_ipv6_src_ip_low");
	define_custom_static_field<ipv6_client_field<&decltype(ipv6tuple::m_fields)::m_sip, 2>>(
	        ret,
	        "socket_ipv6_src_ip_high");

	define_custom_static_field<ipv6_client_field<&decltype(ipv6tuple::m_fields)::m_dip, 0>>(
	        ret,
	        "socket_ipv6_dest_ip_low");
	define_custom_static_field<ipv6_client_field<&decltype(ipv6tuple::m_fields)::m_dip, 2>>(
	        ret,
	        "socket_ipv6_dest_ip_high");

	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv6info,
	                           &ipv6tuple::m_fields,
	                           &decltype(ipv6tuple::m_fields)::m_sport>(ret,
	                                                                    "socket_ipv6_src_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv6info,
	                           &ipv6tuple::m_fields,
	                           &decltype(ipv6tuple::m_fields)::m_dport>(ret,
	                                                                    "socket_ipv6_dst_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv6info,
	                           &ipv6tuple::m_fields,
	                           &decltype(ipv6tuple::m_fields)::m_l4proto>(ret,
	                                                                      "socket_ipv6_l4_proto");

	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4serverinfo,
	                           &ipv4serverinfo::m_ip>(ret, "socket_ipv4_server_ip");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4serverinfo,
	                           &ipv4serverinfo::m_port>(ret, "socket_ipv4_server_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv4serverinfo,
	                           &ipv4serverinfo::m_l4proto>(ret, "socket_ipv4_server_l4_proto");

	define_custom_static_field<ipv6_server_field<0>>(ret, "socket_ipv6_server_ip_low");
	define_custom_static_field<ipv6_server_field<2>>(ret, "socket_ipv6_server_ip_high");

	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv6serverinfo,
	                           &ipv6serverinfo::m_port>(ret, "socket_ipv6_server_port");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_ipv6serverinfo,
	                           &ipv6serverinfo::m_l4proto>(ret, "socket_ipv6_server_l4_proto");

	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_unixinfo,
	                           &unix_tuple::m_fields,
	                           &decltype(unix_tuple::m_fields)::m_source>(ret, "socket_unix_src");
	define_static_member_field<&self::m_sockinfo,
	                           &sinsp_sockinfo::m_unixinfo,
	                           &unix_tuple::m_fields,
	                           &decltype(unix_tuple::m_fields)::m_dest>(ret, "socket_unix_dest");

	return ret;
}

std::string sinsp_fdinfo::tostring_clean() const {
	std::string tstr = m_name;
	sanitize_string(tstr);

	return tstr;
}

void sinsp_fdinfo::add_filename_raw(std::string_view rawpath) {
	m_name_raw = std::string(rawpath);
}

void sinsp_fdinfo::add_filename(std::string_view fullpath) {
	m_name = std::string(fullpath);
}

void sinsp_fdinfo::set_net_role_by_guessing(const sinsp_threadinfo& ptinfo, const bool incoming) {
	//
	// If this process owns the port, mark it as server, otherwise mark it as client
	//
	if(!ptinfo.is_bound_to_port(m_sockinfo.m_ipv4info.m_fields.m_dport)) {
		set_role_client();
		return;
	}

	if(!ptinfo.uses_client_port(m_sockinfo.m_ipv4info.m_fields.m_sport)) {
		set_role_server();
		return;
	}

	if(!(m_flags & (sinsp_fdinfo::FLAGS_ROLE_CLIENT | sinsp_fdinfo::FLAGS_ROLE_SERVER))) {
		// We just assume that a server usually starts with a read and a client with a write.
		if(incoming) {
			set_role_server();
		} else {
			set_role_client();
		}
	}
}

scap_l4_proto sinsp_fdinfo::get_l4proto() const {
	scap_fd_type evt_type = m_type;

	if(evt_type == SCAP_FD_IPV4_SOCK) {
		if((scap_l4_proto)m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW) {
			return SCAP_L4_RAW;
		}

		if(is_role_none()) {
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv4info.m_fields.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV4_SERVSOCK) {
		return (scap_l4_proto)(m_sockinfo.m_ipv4serverinfo.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV6_SOCK) {
		if((scap_l4_proto)m_sockinfo.m_ipv6info.m_fields.m_l4proto == SCAP_L4_RAW) {
			return SCAP_L4_RAW;
		}

		if(is_role_none()) {
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv6info.m_fields.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV6_SERVSOCK) {
		return (scap_l4_proto)(m_sockinfo.m_ipv6serverinfo.m_l4proto);
	} else {
		return SCAP_L4_NA;
	}
}
