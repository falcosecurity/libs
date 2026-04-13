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
#include <unistd.h>
#include <limits.h>
#endif
#include <stdio.h>
#include <libscap/strl.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>
#include <libsinsp/user.h>

extern sinsp_evttables g_infotables;

static void copy_ipv6_address(uint32_t (&dest)[4], const uint32_t (&src)[4]) {
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

template<typename SyncPolicy>
sinsp_threadinfo_impl<SyncPolicy>::sinsp_threadinfo_impl(
        const std::shared_ptr<ctor_params>& params):
        extensible_struct(params->thread_manager_dyn_fields),
        m_params{params},
        m_fdtable{params->fdtable_factory.create()},
        m_main_fdtable(m_fdtable.table_ptr()),
        m_args_table_adapter("args", m_args),
        m_env_table_adapter("env", m_env),
        m_cgroups_table_adapter("cgroups", m_cgroups) {
	init();
}

template<typename SyncPolicy>
#if defined(__clang__)
__attribute__((no_sanitize("undefined")))
#endif
libsinsp::state::static_field_infos
sinsp_threadinfo_impl<SyncPolicy>::get_static_fields() {
	using self = sinsp_threadinfo_impl<SyncPolicy>;

	libsinsp::state::static_field_infos ret;
	// todo(jasondellaluce): support missing fields that are vectors, maps, or sub-tables
	DEFINE_STATIC_FIELD(ret, self, m_tid, "tid");
	DEFINE_STATIC_FIELD(ret, self, m_pid, "pid");
	DEFINE_STATIC_FIELD(ret, self, m_ptid, "ptid");
	DEFINE_STATIC_FIELD(ret, self, m_reaper_tid, "reaper_tid");
	DEFINE_STATIC_FIELD(ret, self, m_sid, "sid");
	DEFINE_STATIC_FIELD(ret, self, m_comm, "comm");
	DEFINE_STATIC_FIELD(ret, self, m_exe, "exe");
	DEFINE_STATIC_FIELD(ret, self, m_exepath, "exe_path");
	DEFINE_STATIC_FIELD(ret, self, m_exe_writable, "exe_writable");
	DEFINE_STATIC_FIELD(ret, self, m_exe_upper_layer, "exe_upper_layer");
	DEFINE_STATIC_FIELD(ret, self, m_exe_lower_layer, "exe_lower_layer");
	DEFINE_STATIC_FIELD(ret, self, m_exe_from_memfd, "exe_from_memfd");
	const auto table_ptr_offset = libsinsp::state::extensible_table<uint64_t>::table_ptr_offset();
	libsinsp::state::define_static_field<libsinsp::state::base_table*>(
	        ret,
	        OFFSETOF_STATIC_FIELD(self, m_args_table_adapter) + table_ptr_offset,
	        "args",
	        true);
	libsinsp::state::define_static_field<libsinsp::state::base_table*>(
	        ret,
	        OFFSETOF_STATIC_FIELD(self, m_env_table_adapter) + table_ptr_offset,
	        "env",
	        true);
	libsinsp::state::define_static_field<libsinsp::state::base_table*>(
	        ret,
	        OFFSETOF_STATIC_FIELD(self, m_cgroups_table_adapter) + table_ptr_offset,
	        "cgroups",
	        true);
	DEFINE_STATIC_FIELD(ret, self, m_flags, "flags");
	DEFINE_STATIC_FIELD(ret, self, m_fdlimit, "fd_limit");
	DEFINE_STATIC_FIELD(ret, self, m_uid, "uid");
	DEFINE_STATIC_FIELD(ret, self, m_gid, "gid");
	DEFINE_STATIC_FIELD(ret, self, m_loginuid, "loginuid");
	// m_cap_permitted
	// m_cap_effective
	// m_cap_inheritable
	DEFINE_STATIC_FIELD(ret, self, m_exe_ino, "exe_ino");
	DEFINE_STATIC_FIELD(ret, self, m_exe_ino_ctime, "exe_ino_ctime");
	DEFINE_STATIC_FIELD(ret, self, m_exe_ino_mtime, "exe_ino_mtime");
	// m_exe_ino_ctime_duration_clone_ts
	// m_exe_ino_ctime_duration_pidns_start
	// m_vmsize_kb
	// m_vmrss_kb
	// m_vmswap_kb
	// m_pfmajor
	// m_pfminor
	DEFINE_STATIC_FIELD(ret, self, m_vtid, "vtid");
	DEFINE_STATIC_FIELD(ret, self, m_vpid, "vpid");
	DEFINE_STATIC_FIELD(ret, self, m_vpgid, "vpgid");
	DEFINE_STATIC_FIELD(ret, self, m_pgid, "pgid");
	DEFINE_STATIC_FIELD(ret, self, m_pidns_init_start_ts, "pidns_init_start_ts");
	DEFINE_STATIC_FIELD(ret, self, m_root, "root");
	DEFINE_STATIC_FIELD(ret, self, m_tty, "tty");
	// m_category
	// m_clone_ts
	// m_lastexec_ts
	// m_latency
	DEFINE_STATIC_FIELD_READONLY(ret, self, m_main_fdtable, "file_descriptors");
	DEFINE_STATIC_FIELD_READONLY(ret, self, m_cwd, "cwd");
	// m_parent_loop_detected
	return ret;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::init() {
	m_pid = (uint64_t)-1LL;
	m_sid = (uint64_t)-1LL;
	m_ptid = (uint64_t)-1LL;
	m_vpgid = (uint64_t)-1LL;
	m_pgid = (uint64_t)-1LL;
	m_uid = 0xffffffff;
	m_gid = 0xffffffff;
	m_loginuid = 0xffffffff;
	set_lastevent_data_validity(false);
	m_reaper_tid = -1;
	m_not_expired_children = 0;
	set_lastevent_type((uint16_t)-1);
	set_lastevent_ts(0);
	set_prevevent_ts(0);
	set_lastaccess_ts(0);
	set_clone_ts(0);
	set_lastexec_ts(0);
	get_lastevent_category().m_category = EC_UNKNOWN;
	m_flags = PPM_CL_NAME_CHANGED;
	m_fdlimit = -1;
	m_vmsize_kb = 0;
	m_vmrss_kb = 0;
	m_vmswap_kb = 0;
	m_pfmajor = 0;
	m_pfminor = 0;
	m_vtid = -1;
	m_vpid = -1;
	m_pidns_init_start_ts = 0;
	set_lastevent_fd(0);
	set_last_event_data(nullptr);
	m_parent_loop_detected = false;
	m_tty = 0;
	m_cap_inheritable = 0;
	m_cap_permitted = 0;
	m_cap_effective = 0;
	m_exe_ino = 0;
	m_exe_ino_ctime = 0;
	m_exe_ino_mtime = 0;
	m_exe_ino_ctime_duration_clone_ts = 0;
	m_exe_ino_ctime_duration_pidns_start = 0;
	m_filtered_out = false;
	m_exe_writable = false;
	m_exe_upper_layer = false;
	m_exe_lower_layer = false;
	m_exe_from_memfd = false;
}

template<typename SyncPolicy>
sinsp_threadinfo_impl<SyncPolicy>::~sinsp_threadinfo_impl() {
	if(m_lastevent_data) {
		free(m_lastevent_data);
	}
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::fix_sockets_coming_from_proc(
        const std::set<uint16_t>& ipv4_server_ports,
        const bool resolve_hostname_and_port) {
	m_fdtable.loop([resolve_hostname_and_port, &ipv4_server_ports](int64_t fd, sinsp_fdinfo& fdi) {
		if(fdi.m_type != SCAP_FD_IPV4_SOCK) {
			return true;
		}

		auto& ipv4_tuple = fdi.m_sockinfo.m_ipv4info;
		auto& ipv4_tuple_fields = ipv4_tuple.m_fields;

		if(ipv4_server_ports.find(ipv4_tuple_fields.m_sport) == ipv4_server_ports.end()) {
			fdi.set_role_client();
			return true;
		}

		const uint32_t tip = ipv4_tuple_fields.m_sip;
		const uint16_t tport = ipv4_tuple_fields.m_sport;
		ipv4_tuple_fields.m_sip = ipv4_tuple_fields.m_dip;
		ipv4_tuple_fields.m_dip = tip;
		ipv4_tuple_fields.m_sport = ipv4_tuple_fields.m_dport;
		ipv4_tuple_fields.m_dport = tport;
		fdi.m_name = ipv4tuple_to_string(ipv4_tuple, resolve_hostname_and_port);
		fdi.set_role_server();
		return true;
	});
}

template<typename SyncPolicy>
std::shared_ptr<sinsp_fdinfo> sinsp_threadinfo_impl<SyncPolicy>::add_fd_from_scap(
        const scap_fdinfo& fdi,
        const bool resolve_hostname_and_port) {
	auto newfdi = m_params->fdinfo_factory.create();

	newfdi->m_type = fdi.type;
	newfdi->m_openflags = 0;
	newfdi->m_type = fdi.type;
	newfdi->m_flags = sinsp_fdinfo::FLAGS_FROM_PROC;
	newfdi->m_ino = fdi.ino;
	newfdi->m_fd = fdi.fd;

	switch(newfdi->m_type) {
	case SCAP_FD_IPV4_SOCK:
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi.info.ipv4info.sip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi.info.ipv4info.dip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi.info.ipv4info.sport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi.info.ipv4info.dport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi.info.ipv4info.l4proto;
		if(fdi.info.ipv4info.l4proto == SCAP_L4_TCP) {
			newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
		}
		m_params->network_interfaces.update_fd(*newfdi);
		newfdi->m_name =
		        ipv4tuple_to_string(newfdi->m_sockinfo.m_ipv4info, resolve_hostname_and_port);
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		newfdi->m_sockinfo.m_ipv4serverinfo.m_ip = fdi.info.ipv4serverinfo.ip;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_port = fdi.info.ipv4serverinfo.port;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi.info.ipv4serverinfo.l4proto;
		newfdi->m_name = ipv4serveraddr_to_string(newfdi->m_sockinfo.m_ipv4serverinfo,
		                                          resolve_hostname_and_port);
		break;
	case SCAP_FD_IPV6_SOCK:
		if(sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi.info.ipv6info.sip) &&
		   sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi.info.ipv6info.dip)) {
			//
			// This is an IPv4-mapped IPv6 addresses
			// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses). Convert it into the
			// IPv4 representation.
			//
			newfdi->m_type = SCAP_FD_IPV4_SOCK;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi.info.ipv6info.sip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi.info.ipv6info.dip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi.info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi.info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi.info.ipv6info.l4proto;
			if(fdi.info.ipv6info.l4proto == SCAP_L4_TCP) {
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			m_params->network_interfaces.update_fd(*newfdi);
			newfdi->m_name =
			        ipv4tuple_to_string(newfdi->m_sockinfo.m_ipv4info, resolve_hostname_and_port);
		} else {
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b,
			                  fdi.info.ipv6info.sip);
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b,
			                  fdi.info.ipv6info.dip);
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_sport = fdi.info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_dport = fdi.info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi.info.ipv6info.l4proto;
			if(fdi.info.ipv6info.l4proto == SCAP_L4_TCP) {
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			newfdi->m_name =
			        ipv6tuple_to_string(newfdi->m_sockinfo.m_ipv6info, resolve_hostname_and_port);
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(newfdi->m_sockinfo.m_ipv6serverinfo.m_ip.m_b, fdi.info.ipv6serverinfo.ip);
		newfdi->m_sockinfo.m_ipv6serverinfo.m_port = fdi.info.ipv6serverinfo.port;
		newfdi->m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi.info.ipv6serverinfo.l4proto;
		newfdi->m_name = ipv6serveraddr_to_string(newfdi->m_sockinfo.m_ipv6serverinfo,
		                                          resolve_hostname_and_port);
		break;
	case SCAP_FD_UNIX_SOCK:
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_source = fdi.info.unix_socket_info.source;
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_dest = fdi.info.unix_socket_info.destination;
		newfdi->m_name = fdi.info.unix_socket_info.fname;
		if(newfdi->m_name.empty()) {
			newfdi->set_role_client();
		} else {
			newfdi->set_role_server();
		}
		break;
	case SCAP_FD_FILE_V2:
		newfdi->m_openflags = fdi.info.regularinfo.open_flags;
		newfdi->m_name = fdi.info.regularinfo.fname;
		newfdi->m_dev = fdi.info.regularinfo.dev;
		newfdi->m_mount_id = fdi.info.regularinfo.mount_id;
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_EVENT:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
	case SCAP_FD_BPF:
	case SCAP_FD_USERFAULTFD:
	case SCAP_FD_IOURING:
	case SCAP_FD_MEMFD:
	case SCAP_FD_PIDFD:
		newfdi->m_name = fdi.info.fname;
		break;
	default:
		ASSERT(false);
		return nullptr;
	}

	// Add the FD to the table and returns a pointer to it.
	return m_fdtable.add(fdi.fd, std::move(newfdi));
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::init(const scap_threadinfo& pinfo,
                                             const bool can_load_env_from_proc) {
	init();

	m_tid = pinfo.tid;
	m_pid = pinfo.pid;
	m_ptid = pinfo.ptid;
	m_sid = pinfo.sid;
	m_vpgid = pinfo.vpgid;
	m_pgid = pinfo.pgid;

	m_comm = pinfo.comm;
	m_exe = pinfo.exe;
	/* The exepath is extracted from `/proc/pid/exe`. */
	set_exepath(std::string(pinfo.exepath));
	m_exe_writable = pinfo.exe_writable;
	m_exe_upper_layer = pinfo.exe_upper_layer;
	m_exe_lower_layer = pinfo.exe_lower_layer;
	m_exe_from_memfd = pinfo.exe_from_memfd;

	/* We cannot obtain the reaper_tid from a /proc scan */
	m_reaper_tid = -1;
	m_not_expired_children = 0;

	set_args(pinfo.args, pinfo.args_len);
	if(is_main_thread()) {
		set_env(pinfo.env, pinfo.env_len, can_load_env_from_proc);
		update_cwd({pinfo.cwd});
	}
	m_flags |= pinfo.flags;
	m_flags |= PPM_CL_ACTIVE;  // Assume that all the threads coming from /proc are real, active
	                           // threads
	m_fdtable.clear();
	m_fdtable.set_tid(m_tid);
	m_fdlimit = pinfo.fdlimit;

	m_cap_permitted = pinfo.cap_permitted;
	m_cap_effective = pinfo.cap_effective;
	m_cap_inheritable = pinfo.cap_inheritable;

	m_exe_ino = pinfo.exe_ino;
	m_exe_ino_ctime = pinfo.exe_ino_ctime;
	m_exe_ino_mtime = pinfo.exe_ino_mtime;
	m_exe_ino_ctime_duration_clone_ts = pinfo.exe_ino_ctime_duration_clone_ts;
	m_exe_ino_ctime_duration_pidns_start = pinfo.exe_ino_ctime_duration_pidns_start;

	m_vmsize_kb = pinfo.vmsize_kb;
	m_vmrss_kb = pinfo.vmrss_kb;
	m_vmswap_kb = pinfo.vmswap_kb;
	m_pfmajor = pinfo.pfmajor;
	m_pfminor = pinfo.pfminor;
	m_vtid = pinfo.vtid;
	m_vpid = pinfo.vpid;
	m_pidns_init_start_ts = pinfo.pidns_init_start_ts;
	set_clone_ts(pinfo.clone_ts);
	set_lastexec_ts(0);
	m_tty = pinfo.tty;

	set_cgroups(pinfo.cgroups.path, pinfo.cgroups.len);
	m_root = pinfo.root;

	m_gid = pinfo.gid;
	m_uid = pinfo.uid;
	m_loginuid = pinfo.loginuid;
}

template<typename SyncPolicy>
const typename sinsp_threadinfo_impl<SyncPolicy>::cgroups_t&
sinsp_threadinfo_impl<SyncPolicy>::cgroups() const {
	return m_cgroups;
}

template<typename SyncPolicy>
typename sinsp_threadinfo_impl<SyncPolicy>::cgroups_t
sinsp_threadinfo_impl<SyncPolicy>::get_cgroups() const {
	std::shared_lock l(m_state_mutex);
	return m_cgroups;
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_comm() const {
	std::shared_lock l(m_state_mutex);
	return m_comm;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_comm(std::string v) {
	std::unique_lock l(m_state_mutex);
	m_comm = std::move(v);
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_exe() const {
	std::shared_lock l(m_state_mutex);
	return m_exe;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe(std::string v) {
	std::unique_lock l(m_state_mutex);
	m_exe = std::move(v);
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_exepath() const {
	std::shared_lock l(m_state_mutex);
	return m_exepath;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::get_exe_writable() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_writable;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_writable(bool v) {
	std::unique_lock l(m_state_mutex);
	m_exe_writable = v;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::get_exe_upper_layer() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_upper_layer;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_upper_layer(bool v) {
	std::unique_lock l(m_state_mutex);
	m_exe_upper_layer = v;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::get_exe_lower_layer() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_lower_layer;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_lower_layer(bool v) {
	std::unique_lock l(m_state_mutex);
	m_exe_lower_layer = v;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::get_exe_from_memfd() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_from_memfd;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_from_memfd(bool v) {
	std::unique_lock l(m_state_mutex);
	m_exe_from_memfd = v;
}

template<typename SyncPolicy>
std::vector<std::string> sinsp_threadinfo_impl<SyncPolicy>::get_args() const {
	std::shared_lock l(m_state_mutex);
	return m_args;
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_cmd_line() const {
	std::shared_lock l(m_state_mutex);
	return m_cmd_line;
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_root() const {
	std::shared_lock l(m_state_mutex);
	return m_root;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_root(std::string v) {
	std::unique_lock l(m_state_mutex);
	m_root = std::move(v);
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_exe_ino() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_ino;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_ino(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_exe_ino = v;
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_exe_ino_ctime() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_ino_ctime;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_ino_ctime(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_exe_ino_ctime = v;
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_exe_ino_mtime() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_ino_mtime;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_ino_mtime(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_exe_ino_mtime = v;
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_exe_ino_ctime_duration_clone_ts() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_ino_ctime_duration_clone_ts;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_ino_ctime_duration_clone_ts(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_exe_ino_ctime_duration_clone_ts = v;
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_exe_ino_ctime_duration_pidns_start() const {
	std::shared_lock l(m_state_mutex);
	return m_exe_ino_ctime_duration_pidns_start;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exe_ino_ctime_duration_pidns_start(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_exe_ino_ctime_duration_pidns_start = v;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_env(const std::vector<std::string>& env) {
	std::unique_lock l(m_state_mutex);
	m_env = env;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_args(const char* args, size_t len) {
	if(len > 0 && args[len - 1] == '\0') {
		len--;
	}

	set_args(sinsp_split({args, len}, '\0'));
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_args(const std::vector<std::string>& args) {
	std::unique_lock l(m_state_mutex);
	m_args = args;
	m_cmd_line = m_comm;
	if(!m_cmd_line.empty()) {
		for(const auto& arg : m_args) {
			m_cmd_line += " ";
			m_cmd_line += arg;
		}
	}
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_env(const char* const env,
                                                size_t len,
                                                const bool can_load_from_proc) {
	if(len == SCAP_MAX_ENV_SIZE && can_load_from_proc) {
		if(set_env_from_proc()) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Large environment for process %lu [%s], loaded from /proc",
			                          m_pid,
			                          m_comm.c_str());
			return;
		}

		libsinsp_logger()->format(sinsp_logger::SEV_INFO,
		                          "Failed to load environment for process %lu [%s] from /proc, "
		                          "using first %d bytes",
		                          m_pid,
		                          m_comm.c_str(),
		                          SCAP_MAX_ENV_SIZE);
	}

	if(len > 0 && env[len - 1] == '\0') {
		len--;
	}

	auto new_env = sinsp_split({env, len}, '\0');
	std::unique_lock l(m_state_mutex);
	m_env = std::move(new_env);
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::set_env_from_proc() {
	std::string environ_path =
	        std::string(scap_get_host_root()) + "/proc/" + std::to_string(m_pid) + "/environ";

	std::ifstream environment(environ_path);
	if(!environment) {
		return false;
	}

	std::vector<std::string> new_env;
	while(environment) {
		std::string env;
		getline(environment, env, '\0');
		if(!env.empty()) {
			new_env.emplace_back(env);
		}
	}

	std::unique_lock l(m_state_mutex);
	m_env = std::move(new_env);
	return true;
}

template<typename SyncPolicy>
std::vector<std::string> sinsp_threadinfo_impl<SyncPolicy>::get_env() {
	if(is_main_thread()) {
		std::shared_lock l(m_state_mutex);
		return m_env;
	}
	auto mtinfo = get_main_thread();
	if(mtinfo) {
		return mtinfo->get_env();
	}
	std::shared_lock l(m_state_mutex);
	return m_env;
}

// Return value string for the exact environment variable name given
template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_env(const std::string& name) {
	size_t nlen = name.length();
	for(const auto& env_var : get_env()) {
		if((env_var.length() > (nlen + 1)) && (env_var[nlen] == '=') &&
		   !env_var.compare(0, nlen, name)) {
			// Stripping spaces, not sure if we really should or need to
			size_t first = env_var.find_first_not_of(' ', nlen + 1);
			if(first == std::string::npos)
				return "";
			size_t last = env_var.find_last_not_of(' ');

			return env_var.substr(first, last - first + 1);
		}
	}

	return "";
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::concatenate_all_env() {
	const auto& all_env = get_env();
	if(all_env.size() == 0) {
		return "";
	}

	// Here we have at least one env so we can pop the last character at the end of the loop.
	std::string concatenate_env;
	for(const auto& env_var : all_env) {
		concatenate_env += env_var;
		concatenate_env += ' ';
	}
	concatenate_env.pop_back();
	return concatenate_env;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_cgroups(const char* cgroups, size_t len) {
	if(len > 0 && cgroups[len - 1] == '\0') {
		len--;
	}

	set_cgroups(sinsp_split({cgroups, len}, '\0'));
}

template<typename SyncPolicy>
typename sinsp_threadinfo_impl<SyncPolicy>::cgroups_t
sinsp_threadinfo_impl<SyncPolicy>::parse_cgroups(const std::vector<std::string>& defs) {
	cgroups_t result;
	for(const auto& def : defs) {
		std::string::size_type eq_pos = def.find("=");
		if(eq_pos == std::string::npos) {
			return result;
		}

		std::string subsys = def.substr(0, eq_pos);
		std::string cgroup = def.substr(eq_pos + 1);

		size_t pos = subsys.find("_cgroup");
		if(pos != std::string::npos) {
			subsys.erase(pos, sizeof("_cgroup") - 1);
		}

		if(subsys == "perf") {
			subsys = "perf_event";
		} else if(subsys == "mem") {
			subsys = "memory";
		} else if(subsys == "io") {
			// blkio has been renamed just `io` in kernel space
			subsys = "blkio";
		}

		result.emplace_back(subsys, cgroup);
	}
	return result;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_cgroups(const std::vector<std::string>& cgroups) {
	std::unique_lock l(m_state_mutex);
	m_cgroups = parse_cgroups(cgroups);
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_cgroups(const cgroups_t& cgroups) {
	std::unique_lock l(m_state_mutex);
	m_cgroups = cgroups;
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_lastexec_ts() const {
	std::shared_lock l(m_state_mutex);
	return m_lastexec_ts;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_lastexec_ts(uint64_t v) {
	std::unique_lock l(m_state_mutex);
	m_lastexec_ts = v;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::apply_exec_state(const exec_state_t& state) {
	std::unique_lock l(m_state_mutex);

	// Mutex-protected exec-info only. Caller must set m_pid before this if using
	// load_env_from_proc.
	m_exe = state.exe;
	m_lastexec_ts = state.lastexec_ts;
	m_comm = state.comm;
	m_args = state.args;
	m_cmd_line = m_comm;
	if(!m_cmd_line.empty()) {
		for(const auto& arg : m_args) {
			m_cmd_line += " ";
			m_cmd_line += arg;
		}
	}
	if(state.exepath.has_value()) {
		m_exepath = *state.exepath;
		constexpr char suffix[] = " (deleted)";
		constexpr size_t suffix_len = sizeof(suffix) - 1;
		if(m_exepath.size() > suffix_len &&
		   m_exepath.compare(m_exepath.size() - suffix_len, suffix_len, suffix) == 0) {
			m_exepath.resize(m_exepath.size() - suffix_len);
		}
	}
	if(state.exe_writable.has_value()) {
		m_exe_writable = *state.exe_writable;
	}
	if(state.exe_upper_layer.has_value()) {
		m_exe_upper_layer = *state.exe_upper_layer;
	}
	if(state.exe_lower_layer.has_value()) {
		m_exe_lower_layer = *state.exe_lower_layer;
	}
	if(state.exe_from_memfd.has_value()) {
		m_exe_from_memfd = *state.exe_from_memfd;
	}
	if(state.exe_ino.has_value()) {
		m_exe_ino = *state.exe_ino;
	}
	if(state.exe_ino_ctime.has_value()) {
		m_exe_ino_ctime = *state.exe_ino_ctime;
	}
	if(state.exe_ino_mtime.has_value()) {
		m_exe_ino_mtime = *state.exe_ino_mtime;
	}
	if(state.exe_ino_ctime_duration_clone_ts.has_value()) {
		m_exe_ino_ctime_duration_clone_ts = *state.exe_ino_ctime_duration_clone_ts;
	}
	if(state.exe_ino_ctime_duration_pidns_start.has_value()) {
		m_exe_ino_ctime_duration_pidns_start = *state.exe_ino_ctime_duration_pidns_start;
	}
	if(state.cgroups.has_value()) {
		m_cgroups = *state.cgroups;
	}
	if(state.env.has_value()) {
		m_env = *state.env;
	} else if(state.load_env_from_proc) {
		if(set_env_from_proc()) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Large environment for process %lu [%s], loaded from /proc",
			                          m_pid,
			                          m_comm.c_str());
		} else {
			libsinsp_logger()->format(sinsp_logger::SEV_INFO,
			                          "Failed to load environment for process %lu [%s] from /proc, "
			                          "using first %d bytes",
			                          m_pid,
			                          m_comm.c_str(),
			                          SCAP_MAX_ENV_SIZE);
		}
	}
}

template<typename SyncPolicy>
std::shared_ptr<sinsp_fdinfo> sinsp_threadinfo_impl<SyncPolicy>::add_fd(
        int64_t fd,
        std::shared_ptr<sinsp_fdinfo>&& fdinfo) {
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL) {
		return nullptr;
	}
	auto res = fd_table_ptr->add(fd, std::move(fdinfo));

	set_lastevent_fd(fd);

	return res;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::remove_fd(int64_t fd) {
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL) {
		return;
	}
	fd_table_ptr->erase(fd);
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::loop_fds(sinsp_fdtable::fdtable_const_visitor_t visitor) {
	sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL) {
		return false;
	}

	return fdt->const_loop(visitor);
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::is_bound_to_port(uint16_t number) const {
	const sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL) {
		return false;
	}

	bool ret = false;
	fdt->const_loop([&](int64_t fd, const sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK) {
			if(fdi.m_sockinfo.m_ipv4info.m_fields.m_dport == number) {
				// set result and break out of the loop
				ret = true;
				return false;
			}
		} else if(fdi.m_type == SCAP_FD_IPV4_SERVSOCK) {
			if(fdi.m_sockinfo.m_ipv4serverinfo.m_port == number) {
				// set result and break out of the loop
				ret = true;
				return false;
			}
		}
		return true;
	});

	return ret;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::uses_client_port(uint16_t number) const {
	const sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL) {
		return false;
	}

	bool ret = false;
	fdt->const_loop([&](int64_t fd, const sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK) {
			if(fdi.m_sockinfo.m_ipv4info.m_fields.m_sport == number) {
				// set result and break out of the loop
				ret = true;
				return false;
			}
		}
		return true;
	});

	return ret;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::is_lastevent_data_valid() const {
	return (get_lastevent_cpuid() != (uint16_t)-1);
}

template<typename SyncPolicy>
sinsp_threadinfo_impl<SyncPolicy>* sinsp_threadinfo_impl<SyncPolicy>::get_cwd_root() {
	if(!(m_flags & PPM_CL_CLONE_FS)) {
		return this;
	} else {
		return get_main_thread().get();
	}
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_cwd() {
	auto tinfo = get_main_thread();
	if(tinfo) {
		std::shared_lock l(tinfo->m_state_mutex);
		return tinfo->m_cwd;
	}
	return "./";
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::update_cwd(std::string_view cwd) {
	auto tinfo = get_main_thread();
	if(!tinfo) {
		return;
	}
	std::unique_lock l(tinfo->m_state_mutex);
	tinfo->m_cwd = sinsp_utils::concatenate_paths(tinfo->m_cwd, cwd);
	if(tinfo->m_cwd.empty() || tinfo->m_cwd.back() != '/') {
		tinfo->m_cwd += '/';
	}
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_fd_usage_pct() {
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0) {
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t)fdlimit);
		if(fd_opencount <= (uint64_t)fdlimit) {
			return (fd_opencount * 100) / fdlimit;
		} else {
			return 100;
		}
	} else {
		return 0;
	}
}

template<typename SyncPolicy>
double sinsp_threadinfo_impl<SyncPolicy>::get_fd_usage_pct_d() {
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0) {
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t)fdlimit);
		if(fd_opencount <= (uint64_t)fdlimit) {
			return ((double)fd_opencount * 100) / fdlimit;
		} else {
			return 100;
		}
	} else {
		return 0;
	}
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_fd_opencount() const {
	auto main_thread = get_main_thread();
	if(main_thread == nullptr) {
		return 0;
	}
	return main_thread->get_fdtable().size();
}

template<typename SyncPolicy>
uint64_t sinsp_threadinfo_impl<SyncPolicy>::get_fd_limit() {
	auto main_thread = get_main_thread();
	if(main_thread == nullptr) {
		return 0;
	}
	return main_thread->get_fdlimit();
}

template<typename SyncPolicy>
const std::string& sinsp_threadinfo_impl<SyncPolicy>::get_cgroup(const std::string& subsys) const {
	static const std::string notfound = "/";

	for(const auto& it : cgroups()) {
		if(it.first == subsys) {
			return it.second;
		}
	}

	return notfound;
}

template<typename SyncPolicy>
bool sinsp_threadinfo_impl<SyncPolicy>::get_cgroup(const std::string& subsys,
                                                   std::string& cgroup) const {
	for(const auto& it : cgroups()) {
		if(it.first == subsys) {
			cgroup = it.second;
			return true;
		}
	}

	return false;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::report_thread_loop(
        const sinsp_threadinfo_impl& looping_thread) {
	// Note we only log a loop once for a given main thread, to avoid flooding logs.
	if(!m_parent_loop_detected) {
		libsinsp_logger()->log(std::string("Loop in parent thread state detected for pid ") +
		                               std::to_string(m_pid) +
		                               ". stopped at tid= " + std::to_string(looping_thread.m_tid) +
		                               " ptid=" + std::to_string(looping_thread.m_ptid),
		                       sinsp_logger::SEV_WARNING);
		m_parent_loop_detected = true;
	}
}

/* We should never call this method if we don't have children to reparent
 * if we want to save some clock cycles
 */
template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::assign_children_to_reaper(sinsp_threadinfo_impl* reaper) {
	if(get_children_count() == 0) {
		return;
	}

	if(reaper == this) {
		throw sinsp_exception("the current process is reaper of itself, this should never happen!");
	}

	if(reaper == nullptr) {
		std::unique_lock lock(m_children_mutex);
		auto it = m_children.begin();
		while(it != m_children.end()) {
			if(!it->expired()) {
				it->lock()->set_ptid(0);
			}
			it = m_children.erase(it);
		}
		m_not_expired_children = 0;
		return;
	}

	/* Lock both mutexes in canonical order (by tid) to prevent lock-order inversion
	 * when different events reparent in opposite order (e.g. A→reaper B and B→reaper A).
	 */
	sinsp_threadinfo_impl* first = (m_tid < reaper->m_tid) ? this : reaper;
	sinsp_threadinfo_impl* second = (m_tid < reaper->m_tid) ? reaper : this;
	std::unique_lock lock1(first->m_children_mutex);
	std::unique_lock lock2(second->m_children_mutex);

	auto it = m_children.begin();
	while(it != m_children.end()) {
		if(!it->expired()) {
			std::shared_ptr<sinsp_threadinfo_impl> c = it->lock();
			reaper->m_children.push_front(c);
			c->set_ptid(reaper->m_tid);
			reaper->m_not_expired_children++;
		}
		it = m_children.erase(it);
	}
	m_not_expired_children = 0;
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::populate_cmdline(std::string& cmdline,
                                                         const sinsp_threadinfo_impl* tinfo) {
	std::shared_lock l(tinfo->m_state_mutex);
	if(tinfo->m_cmd_line.empty()) {
		cmdline = tinfo->m_comm;
		for(const auto& arg : tinfo->m_args) {
			cmdline += " ";
			cmdline += arg;
		}
	} else {
		cmdline = tinfo->m_cmd_line;
	}
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::populate_args(std::string& args,
                                                      const sinsp_threadinfo_impl* tinfo) {
	std::shared_lock l(tinfo->m_state_mutex);
	uint32_t nargs = (uint32_t)tinfo->m_args.size();

	for(uint32_t j = 0; j < nargs; j++) {
		args += tinfo->m_args[j];
		if(j < nargs - 1) {
			args += ' ';
		}
	}
}

template<typename SyncPolicy>
std::string sinsp_threadinfo_impl<SyncPolicy>::get_path_for_dir_fd(int64_t dir_fd) {
	auto dir_fdinfo = get_fd(dir_fd);
	auto dir_name = dir_fdinfo ? dir_fdinfo->get_name() : std::string{};
	if(!dir_fdinfo || dir_name.empty()) {
#ifndef _WIN32  // we will have to implement this for Windows
		// Sad day; we don't have the directory in the tinfo's fd cache.
		// Must manually look it up so we can resolve filenames correctly.
		char proc_path[PATH_MAX];
		char dirfd_path[PATH_MAX];
		int ret;
		snprintf(proc_path,
		         sizeof(proc_path),
		         "%s/proc/%lld/fd/%lld",
		         scap_get_host_root(),
		         (long long)m_pid,
		         (long long)dir_fd);

		ret = readlink(proc_path, dirfd_path, sizeof(dirfd_path) - 1);
		if(ret < 0) {
			libsinsp_logger()->log("Unable to determine path for file descriptor.",
			                       sinsp_logger::SEV_INFO);
			return "";
		}
		dirfd_path[ret] = '\0';
		std::string rel_path_base = dirfd_path;
		sanitize_string(rel_path_base);
		rel_path_base.append("/");
		libsinsp_logger()->log(std::string("Translating to ") + rel_path_base);
		return rel_path_base;
#endif  // _WIN32
	}
	return dir_name;
}

template<typename SyncPolicy>
size_t sinsp_threadinfo_impl<SyncPolicy>::args_len() const {
	return strvec_len(m_args);
}

template<typename SyncPolicy>
size_t sinsp_threadinfo_impl<SyncPolicy>::env_len() const {
	return strvec_len(m_env);
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::args_to_iovec(struct iovec** iov,
                                                      int* iovcnt,
                                                      std::string& rem) const {
	return strvec_to_iovec(m_args, iov, iovcnt, rem);
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::env_to_iovec(struct iovec** iov,
                                                     int* iovcnt,
                                                     std::string& rem) const {
	return strvec_to_iovec(m_env, iov, iovcnt, rem);
}

// Set the provided iovec to the string in str, if it will fit. If it
// won't, copy the portion that will fit to rem and set the iovec to
// rem. Updates alen with the new total length and possibly sets rem
// to any truncated string.
template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::add_to_iovec(const std::string& str,
                                                     const bool include_trailing_null,
                                                     struct iovec& iov,
                                                     uint32_t& alen,
                                                     std::string& rem) const {
	uint32_t len = str.size() + (include_trailing_null ? 1 : 0);
	const char* buf = str.c_str();

	if(len > alen) {
		// The entire string won't fit. Use rem to hold a
		// truncated copy
		rem = str.substr(0, alen - 1);
		buf = rem.c_str();
		len = alen;
	}

	iov.iov_base = (void*)buf;
	iov.iov_len = len;

	alen -= len;
}

// iov will be allocated and must be freed. rem is used to hold a
// possibly truncated final argument.
template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::cgroups_to_iovec(struct iovec** iov,
                                                         int* iovcnt,
                                                         std::string& rem,
                                                         const cgroups_t& cgroups) const {
	uint32_t alen = SCAP_MAX_ARGS_SIZE;
	static const std::string eq = "=";

	// We allocate an iovec big enough to hold all the cgroups and
	// intermediate '=' signs. Based on alen, we might not use all
	// of the iovec.
	*iov = (struct iovec*)malloc((3 * cgroups.size()) * sizeof(struct iovec));
	if(*iov == NULL) {
		throw sinsp_exception("memory allocation error in sinsp_threadinfo::cgroups_to_iovec.");
	}

	*iovcnt = 0;

	for(auto it = cgroups.begin(); it != cgroups.end() && alen > 0; ++it) {
		add_to_iovec(it->first, false, (*iov)[(*iovcnt)++], alen, rem);
		if(alen > 0) {
			add_to_iovec(eq, false, (*iov)[(*iovcnt)++], alen, rem);
		}

		if(alen > 0) {
			add_to_iovec(it->second, true, (*iov)[(*iovcnt)++], alen, rem);
		}
	}
}

template<typename SyncPolicy>
size_t sinsp_threadinfo_impl<SyncPolicy>::strvec_len(const std::vector<std::string>& strs) const {
	size_t totlen = 0;

	for(auto& str : strs) {
		totlen += str.size();
		totlen++;  // Trailing NULL
	}

	return totlen;
}

// iov will be allocated and must be freed. rem is used to hold a
// possibly truncated final argument.
template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::strvec_to_iovec(const std::vector<std::string>& strs,
                                                        struct iovec** iov,
                                                        int* iovcnt,
                                                        std::string& rem) const {
	uint32_t alen = SCAP_MAX_ARGS_SIZE;

	// We allocate an iovec big enough to hold all the entries in
	// strs. Based on alen, we might not use all of the iovec.
	*iov = (struct iovec*)malloc(strs.size() * sizeof(struct iovec));
	if(*iov == NULL) {
		throw sinsp_exception("memory allocation error in sinsp_threadinfo::strvec_to_iovec.");
	}

	*iovcnt = 0;

	for(auto it = strs.begin(); it != strs.end() && alen > 0; ++it) {
		add_to_iovec(*it, true, (*iov)[(*iovcnt)++], alen, rem);
	}
}

template<typename SyncPolicy>
void sinsp_threadinfo_impl<SyncPolicy>::set_exepath(std::string&& exepath) {
	constexpr char suffix[] = " (deleted)";
	constexpr size_t suffix_len = sizeof(suffix) - 1;

	std::unique_lock l(m_state_mutex);
	m_exepath = std::move(exepath);
	if(m_exepath.size() > suffix_len &&
	   m_exepath.compare(m_exepath.size() - suffix_len, suffix_len, suffix) == 0) {
		m_exepath.resize(m_exepath.size() - suffix_len);
	}
}

template class sinsp_threadinfo_impl<sync_policy_default>;
