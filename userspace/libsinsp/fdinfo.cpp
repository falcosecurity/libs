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

static libsinsp::state::borrowed_state_data get_ipv6_addr_low(const ipv6addr& a) {
	uint64_t addr;
	memcpy(&addr, &a.m_b[0], sizeof(uint64_t));
	return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_UINT64>(addr);
};

static libsinsp::state::borrowed_state_data get_ipv6_addr_high(const ipv6addr& a) {
	uint64_t addr;
	memcpy(&addr, &a.m_b[2], sizeof(uint64_t));
	return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_UINT64>(addr);
};

static void set_ipv6_addr_low(ipv6addr& a, const libsinsp::state::borrowed_state_data& state_data) {
	memcpy(&a.m_b[0], &state_data.data().u64, sizeof(uint64_t));
};

static void set_ipv6_addr_high(ipv6addr& a,
                               const libsinsp::state::borrowed_state_data& state_data) {
	memcpy(&a.m_b[2], &state_data.data().u64, sizeof(uint64_t));
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

	libsinsp::state::static_field_infos ret;
	libsinsp::state::define_static_field(
	        ret,
	        "type",
	        SS_PLUGIN_ST_UINT8,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        auto type = static_cast<uint8_t>(c->m_type);
		        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_UINT8, uint8_t>(
		                type);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        uint8_t type;
		        auto c = static_cast<self*>(in);
		        in_data.copy_to<SS_PLUGIN_ST_UINT8, uint8_t>(type);
		        c->m_type = static_cast<scap_fd_type>(type);
	        });

	// the rest fo the fields are more trivial to expose
	DEFINE_STATIC_FIELD(ret, self, m_openflags, "open_flags");
	DEFINE_STATIC_FIELD(ret, self, m_name, "name");
	DEFINE_STATIC_FIELD(ret, self, m_name_raw, "name_raw");
	DEFINE_STATIC_FIELD(ret, self, m_oldname, "old_name");
	DEFINE_STATIC_FIELD(ret, self, m_flags, "flags");
	DEFINE_STATIC_FIELD(ret, self, m_dev, "dev");
	DEFINE_STATIC_FIELD(ret, self, m_mount_id, "mount_id");
	DEFINE_STATIC_FIELD(ret, self, m_ino, "ino");
	DEFINE_STATIC_FIELD(ret, self, m_pid, "pid");
	DEFINE_STATIC_FIELD(ret, self, m_fd, "fd");

	// in this case we have a union, so many of the following exposed fields
	// will point to the same memory areas, but this should not be an issue
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4info.m_fields.m_sip, "socket_ipv4_src_ip");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4info.m_fields.m_dip, "socket_ipv4_dest_dip");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4info.m_fields.m_sport, "socket_ipv4_src_port");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4info.m_fields.m_dport, "socket_ipv4_dst_port");
	DEFINE_STATIC_FIELD(ret,
	                    self,
	                    m_sockinfo.m_ipv4info.m_fields.m_l4proto,
	                    "socket_ipv4_l4_proto");
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_src_ip_low",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_sip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_sip, in_data);
	        });
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_src_ip_high",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_sip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_sip, in_data);
	        });
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_dest_ip_low",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_dip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_dip, in_data);
	        });
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_dest_ip_high",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_dip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_dip, in_data);
	        });
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv6info.m_fields.m_sport, "socket_ipv6_src_port");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv6info.m_fields.m_dport, "socket_ipv6_dst_port");
	DEFINE_STATIC_FIELD(ret,
	                    self,
	                    m_sockinfo.m_ipv6info.m_fields.m_l4proto,
	                    "socket_ipv6_l4_proto");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4serverinfo.m_ip, "socket_ipv4_server_ip");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv4serverinfo.m_port, "socket_ipv4_server_port");
	DEFINE_STATIC_FIELD(ret,
	                    self,
	                    m_sockinfo.m_ipv4serverinfo.m_l4proto,
	                    "socket_ipv4_server_l4_proto");
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_server_ip_low",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6serverinfo.m_ip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6serverinfo.m_ip, in_data);
	        });
	libsinsp::state::define_static_field(
	        ret,
	        "socket_ipv6_server_ip_high",
	        SS_PLUGIN_ST_UINT64,
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6serverinfo.m_ip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_high(c->m_sockinfo.m_ipv6serverinfo.m_ip, in_data);
	        });
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_ipv6serverinfo.m_port, "socket_ipv6_server_port");
	DEFINE_STATIC_FIELD(ret,
	                    self,
	                    m_sockinfo.m_ipv6serverinfo.m_l4proto,
	                    "socket_ipv6_server_l4_proto");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_unixinfo.m_fields.m_source, "socket_unix_src");
	DEFINE_STATIC_FIELD(ret, self, m_sockinfo.m_unixinfo.m_fields.m_dest, "socket_unix_dest");

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
