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

template<typename SyncPolicy>
char sinsp_fdinfo_impl<SyncPolicy>::get_typechar() const {
	switch(load_relaxed(m_type)) {
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

template<typename SyncPolicy>
const char* sinsp_fdinfo_impl<SyncPolicy>::get_typestring() const {
	switch(load_relaxed(m_type)) {
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

template<typename SyncPolicy>
sinsp_fdinfo_impl<SyncPolicy>::sinsp_fdinfo_impl(
        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& dyn_fields):
        extensible_struct(dyn_fields) {}

template<typename SyncPolicy>
#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
libsinsp::state::static_field_infos
sinsp_fdinfo_impl<SyncPolicy>::get_static_fields() {
	using self = sinsp_fdinfo_impl<SyncPolicy>;

	libsinsp::state::static_field_infos ret;
	libsinsp::state::define_static_field<uint8_t>(
	        ret,
	        "type",
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
	libsinsp::state::define_static_field<std::string>(
	        ret,
	        "name",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        auto p = std::atomic_load(&c->m_name);
		        if(p) {
			        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING,
			                                                          std::string>(*p);
		        }
		        static const std::string s_empty;
		        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING, std::string>(
		                s_empty);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        std::string val;
		        in_data.copy_to<SS_PLUGIN_ST_STRING, std::string>(val);
		        std::atomic_store(&c->m_name,
		                          std::make_shared<const std::string>(std::move(val)));
	        });
	libsinsp::state::define_static_field<std::string>(
	        ret,
	        "name_raw",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        auto p = std::atomic_load(&c->m_name_raw);
		        if(p) {
			        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING,
			                                                          std::string>(*p);
		        }
		        static const std::string s_empty;
		        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING, std::string>(
		                s_empty);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        std::string val;
		        in_data.copy_to<SS_PLUGIN_ST_STRING, std::string>(val);
		        std::atomic_store(&c->m_name_raw,
		                          std::make_shared<const std::string>(std::move(val)));
	        });
	libsinsp::state::define_static_field<std::string>(
	        ret,
	        "old_name",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        auto p = std::atomic_load(&c->m_oldname);
		        if(p) {
			        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING,
			                                                          std::string>(*p);
		        }
		        static const std::string s_empty;
		        return libsinsp::state::borrowed_state_data::from<SS_PLUGIN_ST_STRING, std::string>(
		                s_empty);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        std::string val;
		        in_data.copy_to<SS_PLUGIN_ST_STRING, std::string>(val);
		        std::atomic_store(&c->m_oldname,
		                          std::make_shared<const std::string>(std::move(val)));
	        });
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
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_src_ip_low",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_sip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_sip, in_data);
	        });
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_src_ip_high",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_sip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_high(c->m_sockinfo.m_ipv6info.m_fields.m_sip, in_data);
	        });
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_dest_ip_low",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_dip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6info.m_fields.m_dip, in_data);
	        });
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_dest_ip_high",
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
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_server_ip_low",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_low(c->m_sockinfo.m_ipv6serverinfo.m_ip);
	        },
	        [](void* in, size_t, const libsinsp::state::borrowed_state_data& in_data) {
		        auto c = static_cast<self*>(in);
		        set_ipv6_addr_low(c->m_sockinfo.m_ipv6serverinfo.m_ip, in_data);
	        });
	libsinsp::state::define_static_field<uint64_t>(
	        ret,
	        "socket_ipv6_server_ip_high",
	        [](const void* in, size_t) -> libsinsp::state::borrowed_state_data {
		        auto c = static_cast<const self*>(in);
		        return get_ipv6_addr_high(c->m_sockinfo.m_ipv6serverinfo.m_ip);
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

template<typename SyncPolicy>
std::string sinsp_fdinfo_impl<SyncPolicy>::tostring_clean() const {
	auto p = std::atomic_load(&m_name);
	std::string tstr = p ? *p : std::string{};
	std::string storage;
	return std::string(sanitize_string(tstr, storage));
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::add_filename_raw(std::string_view rawpath) {
	auto new_ptr = std::make_shared<const std::string>(rawpath);
	write_guard_type g(m_seq);
	std::atomic_store(&m_name_raw, std::move(new_ptr));
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::add_filename(std::string_view fullpath) {
	auto new_ptr = std::make_shared<const std::string>(fullpath);
	write_guard_type g(m_seq);
	set_name_inner(std::move(new_ptr));
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_net_role_by_guessing(const sinsp_threadinfo& ptinfo,
                                                             const bool incoming) {
	// Read port numbers under seqlock, then release. Do not hold fdinfo protection
	// while calling ptinfo.is_bound_to_port/uses_client_port — they take the
	// fdtable lock, and find_ref() elsewhere takes fdtable then fdinfo, so
	// holding fdinfo here would create lock-order inversion (potential deadlock).
	uint16_t dport, sport;
	m_seq.read([&] {
		dport = m_sockinfo.m_ipv4info.m_fields.m_dport;
		sport = m_sockinfo.m_ipv4info.m_fields.m_sport;
	});
	const bool bound = ptinfo.is_bound_to_port(dport);
	const bool uses_client = ptinfo.uses_client_port(sport);

	write_guard_type g(m_seq);
	if(!bound) {
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_CLIENT);
		return;
	}
	if(!uses_client) {
		fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_SERVER);
		return;
	}
	auto f = load_relaxed(m_flags);
	if(!(f & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER))) {
		if(incoming) {
			fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_SERVER);
		} else {
			fetch_or_relaxed(m_flags, (uint32_t)FLAGS_ROLE_CLIENT);
		}
	}
}

template<typename SyncPolicy>
scap_l4_proto sinsp_fdinfo_impl<SyncPolicy>::get_l4proto() const {
	scap_fd_type evt_type;
	sinsp_sockinfo si;
	uint32_t f;
	m_seq.read([&] {
		evt_type = m_type;
		si = m_sockinfo;
		f = m_flags;
	});
	bool role_none = (f & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;

	if(evt_type == SCAP_FD_IPV4_SOCK) {
		if((scap_l4_proto)si.m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW) {
			return SCAP_L4_RAW;
		}
		if(role_none) {
			return SCAP_L4_NA;
		}
		return (scap_l4_proto)(si.m_ipv4info.m_fields.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV4_SERVSOCK) {
		return (scap_l4_proto)(si.m_ipv4serverinfo.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV6_SOCK) {
		if((scap_l4_proto)si.m_ipv6info.m_fields.m_l4proto == SCAP_L4_RAW) {
			return SCAP_L4_RAW;
		}
		if(role_none) {
			return SCAP_L4_NA;
		}
		return (scap_l4_proto)(si.m_ipv6info.m_fields.m_l4proto);
	} else if(evt_type == SCAP_FD_IPV6_SERVSOCK) {
		return (scap_l4_proto)(si.m_ipv6serverinfo.m_l4proto);
	} else {
		return SCAP_L4_NA;
	}
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_file_info(scap_fd_type type,
                                                  uint32_t openflags,
                                                  uint32_t mount_id,
                                                  uint32_t dev,
                                                  uint64_t ino) {
	write_guard_type g(m_seq);
	m_type = type;
	m_openflags = openflags;
	m_mount_id = mount_id;
	m_dev = dev;
	m_ino = ino;
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::init_socket(scap_fd_type type, scap_l4_proto l4proto) {
	write_guard_type g(m_seq);
	m_type = type;
	m_sockinfo = {};
	if(type == SCAP_FD_IPV4_SOCK || type == SCAP_FD_IPV4_SERVSOCK) {
		m_sockinfo.m_ipv4info.m_fields.m_l4proto = l4proto;
	} else if(type == SCAP_FD_IPV6_SOCK || type == SCAP_FD_IPV6_SERVSOCK) {
		m_sockinfo.m_ipv6info.m_fields.m_l4proto = l4proto;
	}
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_pipe_info(uint64_t ino, uint32_t openflags) {
	write_guard_type g(m_seq);
	m_type = SCAP_FD_FIFO;
	m_ino = ino;
	m_openflags = openflags;
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_memfd_info(uint32_t flags) {
	write_guard_type g(m_seq);
	m_type = SCAP_FD_MEMFD;
	m_openflags = flags;
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_pidfd_info(int64_t pid, uint32_t flags) {
	write_guard_type g(m_seq);
	m_type = SCAP_FD_PIDFD;
	m_pid = pid;
	m_openflags = flags;
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_cloexec(bool enable) {
	write_guard_type g(m_seq);
	if(enable) {
		fetch_or_relaxed(m_openflags, (uint32_t)PPM_O_CLOEXEC);
	} else {
		fetch_and_relaxed(m_openflags, ~(uint32_t)PPM_O_CLOEXEC);
	}
}

template<typename SyncPolicy>
void sinsp_fdinfo_impl<SyncPolicy>::set_unix_socket_info(const uint8_t* packed_data,
                                                         std::string name) {
	auto new_name = std::make_shared<const std::string>(std::move(name));
	write_guard_type g(m_seq);
	const auto* source = packed::un_socktuple::source(packed_data);
	const auto* dest = packed::un_socktuple::dest(packed_data);
	memcpy(&m_sockinfo.m_unixinfo.m_fields.m_source, source, sizeof(uint64_t));
	memcpy(&m_sockinfo.m_unixinfo.m_fields.m_dest, dest, sizeof(uint64_t));
	set_name_inner(std::move(new_name));
}

template class sinsp_fdinfo_impl<sync_policy_default>;
