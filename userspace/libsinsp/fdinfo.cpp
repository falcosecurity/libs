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

sinsp_fdinfo::sinsp_fdinfo(
        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& dyn_fields):
        table_entry(dyn_fields) {}

libsinsp::state::static_struct::field_infos sinsp_fdinfo::static_fields() const {
	libsinsp::state::static_struct::field_infos ret;

	// the m_type is weird because it's a C-defined non-scoped enum, meaning that it
	// should be represented by default as an integer of word-size (e.g. uint32_t in
	// most cases). However, the state and plugin API only supports integers, and so
	// we need to do some smart casting. Our enemy is the platform/compiler dependent
	// integer size with which the enum could be represented, plus the endianess
	// of the targeted architecture
	auto is_big_endian = htonl(12) == 12;  // the chosen number does not matter
	size_t type_byte_offset = is_big_endian ? (sizeof(scap_fd_type) - 1) : 0;
	define_static_field(ret, this, ((uint8_t*)(&m_type))[type_byte_offset], "type");

	// the rest fo the fields are more trivial to expose
	define_static_field(ret, this, m_openflags, "open_flags");
	define_static_field(ret, this, m_name, "name");
	define_static_field(ret, this, m_name_raw, "name_raw");
	define_static_field(ret, this, m_oldname, "old_name");
	define_static_field(ret, this, m_flags, "flags");
	define_static_field(ret, this, m_dev, "dev");
	define_static_field(ret, this, m_mount_id, "mount_id");
	define_static_field(ret, this, m_ino, "ino");
	define_static_field(ret, this, m_pid, "pid");
	define_static_field(ret, this, m_fd, "fd");

	// in this case we have a union, so many of the following exposed fields
	// will point to the same memory areas, but this should not be an issue
	define_static_field(ret, this, m_sockinfo.m_ipv4info.m_fields.m_sip, "socket_ipv4_src_ip");
	define_static_field(ret, this, m_sockinfo.m_ipv4info.m_fields.m_dip, "socket_ipv4_dest_dip");
	define_static_field(ret, this, m_sockinfo.m_ipv4info.m_fields.m_sport, "socket_ipv4_src_port");
	define_static_field(ret, this, m_sockinfo.m_ipv4info.m_fields.m_dport, "socket_ipv4_dst_port");
	define_static_field(ret,
	                    this,
	                    m_sockinfo.m_ipv4info.m_fields.m_l4proto,
	                    "socket_ipv4_l4_proto");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6info.m_fields.m_sip)[0],
	                    "socket_ipv6_src_ip_low");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6info.m_fields.m_sip)[1],
	                    "socket_ipv6_src_ip_high");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6info.m_fields.m_dip)[0],
	                    "socket_ipv6_dest_ip_low");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6info.m_fields.m_dip)[1],
	                    "socket_ipv6_dest_ip_high");
	define_static_field(ret, this, m_sockinfo.m_ipv6info.m_fields.m_sport, "socket_ipv6_src_port");
	define_static_field(ret, this, m_sockinfo.m_ipv6info.m_fields.m_dport, "socket_ipv6_dst_port");
	define_static_field(ret,
	                    this,
	                    m_sockinfo.m_ipv6info.m_fields.m_l4proto,
	                    "socket_ipv6_l4_proto");
	define_static_field(ret, this, m_sockinfo.m_ipv4serverinfo.m_ip, "socket_ipv4_server_ip");
	define_static_field(ret, this, m_sockinfo.m_ipv4serverinfo.m_port, "socket_ipv4_server_port");
	define_static_field(ret,
	                    this,
	                    m_sockinfo.m_ipv4serverinfo.m_l4proto,
	                    "socket_ipv4_server_l4_proto");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6serverinfo.m_ip)[0],
	                    "socket_ipv6_server_ip_low");
	define_static_field(ret,
	                    this,
	                    ((uint64_t*)&m_sockinfo.m_ipv6serverinfo.m_ip)[1],
	                    "socket_ipv6_server_ip_high");
	define_static_field(ret, this, m_sockinfo.m_ipv6serverinfo.m_port, "socket_ipv6_server_port");
	define_static_field(ret,
	                    this,
	                    m_sockinfo.m_ipv6serverinfo.m_l4proto,
	                    "socket_ipv6_server_l4_proto");
	define_static_field(ret, this, m_sockinfo.m_unixinfo.m_fields.m_source, "socket_unix_src");
	define_static_field(ret, this, m_sockinfo.m_unixinfo.m_fields.m_dest, "socket_unix_dest");

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

bool sinsp_fdinfo::set_net_role_by_guessing(sinsp* inspector,
                                            sinsp_threadinfo* ptinfo,
                                            sinsp_fdinfo* pfdinfo,
                                            bool incoming) {
	//
	// If this process owns the port, mark it as server, otherwise mark it as client
	//
	if(ptinfo->is_bound_to_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport)) {
		if(ptinfo->uses_client_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport)) {
			goto wildass_guess;
		}

		pfdinfo->set_role_server();
		return true;
	} else {
		pfdinfo->set_role_client();
		return true;
	}

wildass_guess:
	if(!(pfdinfo->m_flags & (sinsp_fdinfo::FLAGS_ROLE_CLIENT | sinsp_fdinfo::FLAGS_ROLE_SERVER))) {
		//
		// We just assume that a server usually starts with a read and a client with a write
		//
		if(incoming) {
			pfdinfo->set_role_server();
		} else {
			pfdinfo->set_role_client();
		}
	}

	return true;
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

static const auto s_fdtable_static_fields = sinsp_fdinfo().static_fields();

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdtable implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_fdtable::sinsp_fdtable(sinsp* inspector):
        table("file_descriptors", &s_fdtable_static_fields) {
	m_tid = 0;
	m_inspector = inspector;
	if(m_inspector != nullptr) {
		m_sinsp_stats_v2 = m_inspector->get_sinsp_stats_v2();
	} else {
		m_sinsp_stats_v2 = nullptr;
	}
	reset_cache();
}

inline const std::shared_ptr<sinsp_fdinfo>& sinsp_fdtable::find_ref(int64_t fd) {
	//
	// Try looking up in our simple cache
	//
	if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd) {
		if(m_sinsp_stats_v2) {
			m_sinsp_stats_v2->m_n_cached_fd_lookups++;
		}
		return m_last_accessed_fdinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	auto fdit = m_table.find(fd);

	if(fdit == m_table.end()) {
		if(m_sinsp_stats_v2) {
			m_sinsp_stats_v2->m_n_failed_fd_lookups++;
		}
		return m_nullptr_ret;
	} else {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
		}

		m_last_accessed_fd = fd;
		m_last_accessed_fdinfo = fdit->second;
		lookup_device(m_last_accessed_fdinfo.get(), fd);
		return m_last_accessed_fdinfo;
	}
}

inline const std::shared_ptr<sinsp_fdinfo>& sinsp_fdtable::add_ref(
        int64_t fd,
        std::unique_ptr<sinsp_fdinfo> fdinfo) {
	if(fdinfo->dynamic_fields() != dynamic_fields()) {
		throw sinsp_exception("adding entry with incompatible dynamic defs to fd table");
	}

	fdinfo->m_fd = fd;

	//
	// Look for the FD in the table
	//
	auto it = m_table.find(fd);

	// Three possible exits here:
	// 1. fd is not on the table
	//   a. the table size is under the limit so create a new entry
	//   b. table size is over the limit, discard the fd
	// 2. fd is already in the table, replace it
	if(it == m_table.end()) {
		if(m_table.size() < m_inspector->m_max_fdtable_size) {
			//
			// No entry in the table, this is the normal case
			//
			m_last_accessed_fd = -1;
			if(m_sinsp_stats_v2 != nullptr) {
				m_sinsp_stats_v2->m_n_added_fds++;
			}

			return m_table.emplace(fd, std::move(fdinfo)).first->second;
		} else {
			return m_nullptr_ret;
		}
	} else {
		//
		// the fd is already in the table.
		//
		if(it->second->m_flags & sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS) {
			//
			// Sometimes an FD-creating syscall can be called on an FD that is being closed (i.e
			// the close enter has arrived but the close exit has not arrived yet).
			// If this is the case, mark the new entry so that the successive close exit won't
			// destroy it.
			//
			fdinfo->m_flags &= ~sinsp_fdinfo::FLAGS_CLOSE_IN_PROGRESS;
			fdinfo->m_flags |= sinsp_fdinfo::FLAGS_CLOSE_CANCELED;

			m_table[CANCELED_FD_NUMBER] = it->second->clone();
		} else {
			//
			// This can happen if:
			//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened
			//  with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going
			// is a reasonable choice. We include an assertion to catch the situation.
			//
			// XXX Can't have this enabled until the FD_CLOEXEC flag is supported
			// ASSERT(false);
		}

		//
		// Replace the fd as a struct copy
		//
		m_last_accessed_fd = -1;
		it->second = std::move(fdinfo);
		return it->second;
	}
}

bool sinsp_fdtable::erase(int64_t fd) {
	auto fdit = m_table.find(fd);

	if(fd == m_last_accessed_fd) {
		m_last_accessed_fd = -1;
	}

	if(fdit == m_table.end()) {
		//
		// Looks like there's no fd to remove.
		// Either the fd creation event was dropped or (more likely) our logic doesn't support the
		// call that created this fd. The assertion will detect it, while in release mode we just
		// keep going.
		//
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_failed_fd_lookups++;
		}
		return false;
	} else {
		m_table.erase(fdit);
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
			m_sinsp_stats_v2->m_n_removed_fds++;
		}
		return true;
	}
}

void sinsp_fdtable::clear() {
	m_table.clear();
}

size_t sinsp_fdtable::size() const {
	return m_table.size();
}

void sinsp_fdtable::reset_cache() {
	m_last_accessed_fd = -1;
}

void sinsp_fdtable::lookup_device(sinsp_fdinfo* fdi, uint64_t fd) {
#ifndef _WIN32
	if(m_inspector == nullptr || m_inspector->is_offline() ||
	   (m_inspector->is_plugin() && !m_inspector->is_syscall_plugin())) {
		return;
	}

	if(m_tid != 0 && m_tid != (uint64_t)-1 && fdi->is_file() && fdi->m_dev == 0 &&
	   fdi->m_mount_id != 0) {
		char procdir[SCAP_MAX_PATH_SIZE];
		snprintf(procdir, sizeof(procdir), "%s/proc/%ld/", scap_get_host_root(), m_tid);
		fdi->m_dev = scap_get_device_by_mount_id(m_inspector->get_scap_platform(),
		                                         procdir,
		                                         fdi->m_mount_id);
		fdi->m_mount_id = 0;  // don't try again
	}
#endif  // _WIN32
}

sinsp_fdinfo* sinsp_fdtable::find(int64_t fd) {
	return find_ref(fd).get();
}

sinsp_fdinfo* sinsp_fdtable::add(int64_t fd, std::unique_ptr<sinsp_fdinfo> fdinfo) {
	return add_ref(fd, std::move(fdinfo)).get();
}

std::unique_ptr<libsinsp::state::table_entry> sinsp_fdtable::new_entry() const {
	return m_inspector->build_fdinfo();
};

std::shared_ptr<libsinsp::state::table_entry> sinsp_fdtable::get_entry(const int64_t& key) {
	return find_ref(key);
}
