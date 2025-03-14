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
#include <unistd.h>
#include <limits.h>
#endif
#include <stdio.h>
#include <algorithm>
#include <libscap/strl.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>
#include <libsinsp/user.h>

extern sinsp_evttables g_infotables;

static void copy_ipv6_address(uint32_t* dest, uint32_t* src) {
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

sinsp_threadinfo::sinsp_threadinfo(
        const sinsp_fdinfo_factory& fdinfo_factory,
        sinsp* inspector,
        const std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>& dyn_fields):
        table_entry(dyn_fields),
        m_inspector(inspector),
        m_fdinfo_factory{fdinfo_factory},
        m_fdtable{fdinfo_factory, inspector},
        m_main_fdtable(m_fdtable.table_ptr()),
        m_args_table_adapter("args", m_args),
        m_env_table_adapter("env", m_env),
        m_cgroups_table_adapter("cgroups", m_cgroups) {
	init();
}

libsinsp::state::static_struct::field_infos sinsp_threadinfo::static_fields() const {
	return get_static_fields();
}

libsinsp::state::static_struct::field_infos sinsp_threadinfo::get_static_fields() {
	using self = sinsp_threadinfo;

	libsinsp::state::static_struct::field_infos ret;
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
	const auto table_ptr_offset = libsinsp::state::built_in_table<uint64_t>::table_ptr_offset();
	define_static_field<libsinsp::state::base_table*>(
	        ret,
	        OFFSETOF_STATIC_FIELD(self, m_args_table_adapter) + table_ptr_offset,
	        "args",
	        true);
	define_static_field<libsinsp::state::base_table*>(
	        ret,
	        OFFSETOF_STATIC_FIELD(self, m_env_table_adapter) + table_ptr_offset,
	        "env",
	        true);
	define_static_field<libsinsp::state::base_table*>(
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

void sinsp_threadinfo::init() {
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
	m_lastevent_type = -1;
	m_lastevent_ts = 0;
	m_prevevent_ts = 0;
	m_lastaccess_ts = 0;
	m_clone_ts = 0;
	m_lastexec_ts = 0;
	m_lastevent_category.m_category = EC_UNKNOWN;
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
	m_lastevent_fd = 0;
	m_last_latency_entertime = 0;
	m_latency = 0;
	m_lastevent_data = NULL;
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

sinsp_threadinfo::~sinsp_threadinfo() {
	if(m_lastevent_data) {
		free(m_lastevent_data);
	}
}

void sinsp_threadinfo::fix_sockets_coming_from_proc() {
	m_fdtable.loop([this](int64_t fd, sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK) {
			if(m_inspector->m_thread_manager->m_server_ports.find(
			           fdi.m_sockinfo.m_ipv4info.m_fields.m_sport) !=
			   m_inspector->m_thread_manager->m_server_ports.end()) {
				uint32_t tip;
				uint16_t tport;

				tip = fdi.m_sockinfo.m_ipv4info.m_fields.m_sip;
				tport = fdi.m_sockinfo.m_ipv4info.m_fields.m_sport;

				fdi.m_sockinfo.m_ipv4info.m_fields.m_sip = fdi.m_sockinfo.m_ipv4info.m_fields.m_dip;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_dip = tip;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_sport =
				        fdi.m_sockinfo.m_ipv4info.m_fields.m_dport;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_dport = tport;

				fdi.m_name =
				        ipv4tuple_to_string(&fdi.m_sockinfo.m_ipv4info,
				                            m_inspector->is_hostname_and_port_resolution_enabled());

				fdi.set_role_server();
			} else {
				fdi.set_role_client();
			}
		}
		return true;
	});
}

void sinsp_threadinfo::add_fd_from_scap(scap_fdinfo* fdi) {
	auto newfdi = m_fdinfo_factory.create();
	bool do_add = true;

	newfdi->m_type = fdi->type;
	newfdi->m_openflags = 0;
	newfdi->m_type = fdi->type;
	newfdi->m_flags = sinsp_fdinfo::FLAGS_FROM_PROC;
	newfdi->m_ino = fdi->ino;
	newfdi->m_fd = fdi->fd;

	switch(newfdi->m_type) {
	case SCAP_FD_IPV4_SOCK:
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
		if(fdi->info.ipv4info.l4proto == SCAP_L4_TCP) {
			newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
		}
		m_inspector->get_ifaddr_list().update_fd(*newfdi);
		newfdi->m_name =
		        ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info,
		                            m_inspector->is_hostname_and_port_resolution_enabled());
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		newfdi->m_sockinfo.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
		newfdi->m_name =
		        ipv4serveraddr_to_string(&newfdi->m_sockinfo.m_ipv4serverinfo,
		                                 m_inspector->is_hostname_and_port_resolution_enabled());

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(
		        newfdi->m_sockinfo.m_ipv4serverinfo.m_port);

		break;
	case SCAP_FD_IPV6_SOCK:
		if(sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.sip) &&
		   sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.dip)) {
			//
			// This is an IPv4-mapped IPv6 addresses
			// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses). Convert it into the
			// IPv4 representation.
			//
			newfdi->m_type = SCAP_FD_IPV4_SOCK;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv6info.sip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv6info.dip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			if(fdi->info.ipv6info.l4proto == SCAP_L4_TCP) {
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			m_inspector->get_ifaddr_list().update_fd(*newfdi);
			newfdi->m_name =
			        ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info,
			                            m_inspector->is_hostname_and_port_resolution_enabled());
		} else {
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b,
			                  fdi->info.ipv6info.sip);
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b,
			                  fdi->info.ipv6info.dip);
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			if(fdi->info.ipv6info.l4proto == SCAP_L4_TCP) {
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			newfdi->m_name =
			        ipv6tuple_to_string(&newfdi->m_sockinfo.m_ipv6info,
			                            m_inspector->is_hostname_and_port_resolution_enabled());
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(newfdi->m_sockinfo.m_ipv6serverinfo.m_ip.m_b,
		                  fdi->info.ipv6serverinfo.ip);
		newfdi->m_sockinfo.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
		newfdi->m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi->info.ipv6serverinfo.l4proto;
		newfdi->m_name =
		        ipv6serveraddr_to_string(&newfdi->m_sockinfo.m_ipv6serverinfo,
		                                 m_inspector->is_hostname_and_port_resolution_enabled());

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(
		        newfdi->m_sockinfo.m_ipv6serverinfo.m_port);

		break;
	case SCAP_FD_UNIX_SOCK:
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_source = fdi->info.unix_socket_info.source;
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_dest = fdi->info.unix_socket_info.destination;
		newfdi->m_name = fdi->info.unix_socket_info.fname;
		if(newfdi->m_name.empty()) {
			newfdi->set_role_client();
		} else {
			newfdi->set_role_server();
		}
		break;
	case SCAP_FD_FILE_V2:
		newfdi->m_openflags = fdi->info.regularinfo.open_flags;
		newfdi->m_name = fdi->info.regularinfo.fname;
		newfdi->m_dev = fdi->info.regularinfo.dev;
		newfdi->m_mount_id = fdi->info.regularinfo.mount_id;
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
		newfdi->m_name = fdi->info.fname;
		break;
	default:
		ASSERT(false);
		do_add = false;
		break;
	}

	//
	// Add the FD to the table
	//
	if(!do_add) {
		return;
	}

	auto addedfdi = m_fdtable.add(fdi->fd, std::move(newfdi));
	if(m_inspector->m_filter != nullptr && m_inspector->is_capture()) {
		// in case the inspector is configured with an internal filter, we can
		// filter-out thread infos (and their fd infos) to not dump them in
		// captures unless actually used. Here, we simulate an internal event
		// using the new file descriptor info to understand if we can set
		// its thread info as non-filterable.

		// note: just like the case of  PPME_SCAPEVENT_E used for thread info
		// filtering, the usage of PPME_SYSCALL_READ_X is opinionated. This
		// kind of event has been chosen as a tradeoff of a lightweight and
		// usually-ignored event (in the context of filtering), but that is also
		// marked as using a file descriptor so that file-descriptor filter fields
		// can extract meaningful values.
		scap_evt tscapevt = {};
		tscapevt.type = PPME_SYSCALL_READ_X;
		tscapevt.tid = m_tid;
		tscapevt.ts = 0;
		tscapevt.nparams = 0;
		tscapevt.len = sizeof(scap_evt);

		sinsp_evt tevt = {};
		tevt.set_scap_evt(&tscapevt);
		tevt.set_info(&(g_infotables.m_event_info[PPME_SYSCALL_READ_X]));
		tevt.set_cpuid(0);
		tevt.set_num(0);
		tevt.set_inspector(m_inspector);
		tevt.set_tinfo(this);
		tevt.set_fdinfo_ref(nullptr);
		tevt.set_fd_info(addedfdi);
		int64_t tlefd = tevt.get_tinfo()->m_lastevent_fd;
		tevt.get_tinfo()->m_lastevent_fd = fdi->fd;

		if(m_inspector->m_filter->run(&tevt)) {
			// we mark the thread info as non-filterable due to one event
			// using one of its file descriptor has passed the filter
			m_filtered_out = false;
		} else {
			// we can't say if the thread info for this fd is filterable or not,
			// but we can mark the given file descriptor as filterable. This flag
			// will prevent the fd info from being written in captures.
			fdi->type = SCAP_FD_UNINITIALIZED;
		}

		tevt.get_tinfo()->m_lastevent_fd = tlefd;
		m_lastevent_data = NULL;
	}
}

void sinsp_threadinfo::init(scap_threadinfo* pi) {
	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_ptid = pi->ptid;
	m_sid = pi->sid;
	m_vpgid = pi->vpgid;
	m_pgid = pi->pgid;

	m_comm = pi->comm;
	m_exe = pi->exe;
	/* The exepath is extracted from `/proc/pid/exe`. */
	set_exepath(std::string(pi->exepath));
	m_exe_writable = pi->exe_writable;
	m_exe_upper_layer = pi->exe_upper_layer;
	m_exe_lower_layer = pi->exe_lower_layer;
	m_exe_from_memfd = pi->exe_from_memfd;

	/* We cannot obtain the reaper_tid from a /proc scan */
	m_reaper_tid = -1;
	m_not_expired_children = 0;

	set_args(pi->args, pi->args_len);
	if(is_main_thread()) {
		set_env(pi->env, pi->env_len);
		update_cwd({pi->cwd});
	}
	m_flags |= pi->flags;
	m_flags |= PPM_CL_ACTIVE;  // Assume that all the threads coming from /proc are real, active
	                           // threads
	m_fdtable.clear();
	m_fdtable.set_tid(m_tid);
	m_fdlimit = pi->fdlimit;

	m_cap_permitted = pi->cap_permitted;
	m_cap_effective = pi->cap_effective;
	m_cap_inheritable = pi->cap_inheritable;

	m_exe_ino = pi->exe_ino;
	m_exe_ino_ctime = pi->exe_ino_ctime;
	m_exe_ino_mtime = pi->exe_ino_mtime;
	m_exe_ino_ctime_duration_clone_ts = pi->exe_ino_ctime_duration_clone_ts;
	m_exe_ino_ctime_duration_pidns_start = pi->exe_ino_ctime_duration_pidns_start;

	m_vmsize_kb = pi->vmsize_kb;
	m_vmrss_kb = pi->vmrss_kb;
	m_vmswap_kb = pi->vmswap_kb;
	m_pfmajor = pi->pfmajor;
	m_pfminor = pi->pfminor;
	m_vtid = pi->vtid;
	m_vpid = pi->vpid;
	m_pidns_init_start_ts = pi->pidns_init_start_ts;
	m_clone_ts = pi->clone_ts;
	m_lastexec_ts = 0;
	m_tty = pi->tty;

	set_cgroups(pi->cgroups.path, pi->cgroups.len);
	m_root = pi->root;
	ASSERT(m_inspector);

	set_group(pi->gid);
	set_user(pi->uid);
	set_loginuid((uint32_t)pi->loginuid);
}

const sinsp_threadinfo::cgroups_t& sinsp_threadinfo::cgroups() const {
	return m_cgroups;
}

std::string sinsp_threadinfo::get_comm() const {
	return m_comm;
}

std::string sinsp_threadinfo::get_exe() const {
	return m_exe;
}

std::string sinsp_threadinfo::get_exepath() const {
	return m_exepath;
}

std::string sinsp_threadinfo::get_container_id() {
	std::string container_id;

	const auto accessor = m_inspector->m_thread_manager->get_field_accessor(
	        sinsp_thread_manager::s_container_id_field_name);
	if(accessor) {
		get_dynamic_field(*accessor, container_id);
	}
	return container_id;
}

std::string sinsp_threadinfo::get_container_user() {
	std::string user;

	const auto container_id = get_container_id();
	if(!container_id.empty()) {
		auto table = m_inspector->m_thread_manager->get_table(
		        sinsp_thread_manager::s_containers_table_name);
		if(table != nullptr) {
			auto fld = table->get_field<std::string>(
			        sinsp_thread_manager::s_containers_table_field_user);
			auto e = table->get_entry(container_id.c_str());
			e.read_field(fld, user);
		}
	}
	return user;
}

std::string sinsp_threadinfo::get_container_ip() {
	std::string ip;

	const auto container_id = get_container_id();
	if(!container_id.empty()) {
		auto table = m_inspector->m_thread_manager->get_table(
		        sinsp_thread_manager::s_containers_table_name);
		if(table != nullptr) {
			auto fld = table->get_field<std::string>(
			        sinsp_thread_manager::s_containers_table_field_ip);
			auto e = table->get_entry(container_id.c_str());
			e.read_field(fld, ip);
		}
	}
	return ip;
}

void sinsp_threadinfo::set_user(uint32_t uid) {
	const auto container_id = get_container_id();
	m_uid = uid;
	if(const scap_userinfo* user = m_inspector->m_usergroup_manager->get_user(container_id, uid);
	   !user) {
		const auto notify = m_inspector->is_live() || m_inspector->is_syscall_plugin();
		// For uid 0 force set root related infos
		if(uid == 0) {
			m_inspector->m_usergroup_manager
			        ->add_user(container_id, m_pid, uid, m_gid, "root", "/root", {}, notify);
		} else {
			m_inspector->m_usergroup_manager
			        ->add_user(container_id, m_pid, uid, m_gid, {}, {}, {}, notify);
		}
	}
}

void sinsp_threadinfo::set_group(uint32_t gid) {
	const auto container_id = get_container_id();
	m_gid = gid;
	if(const scap_groupinfo* group = m_inspector->m_usergroup_manager->get_group(container_id, gid);
	   !group) {
		const auto notify = m_inspector->is_live() || m_inspector->is_syscall_plugin();
		// For gid 0 force set root related info
		if(gid == 0) {
			m_inspector->m_usergroup_manager->add_group(container_id, m_pid, gid, "root", notify);
		} else {
			m_inspector->m_usergroup_manager->add_group(container_id, m_pid, gid, {}, notify);
		}
	}
}

void sinsp_threadinfo::set_loginuid(uint32_t loginuid) {
	m_loginuid = loginuid;
}

scap_userinfo* sinsp_threadinfo::get_user() {
	auto user = m_inspector->m_usergroup_manager->get_user(get_container_id(), m_uid);
	if(user != nullptr) {
		return user;
	}
	static scap_userinfo usr{};
	usr.uid = m_uid;
	usr.gid = m_gid;
	strlcpy(usr.name, m_uid == 0 ? "root" : "<NA>", sizeof(usr.name));
	strlcpy(usr.homedir, m_uid == 0 ? "/root" : "<NA>", sizeof(usr.homedir));
	strlcpy(usr.shell, "<NA>", sizeof(usr.shell));
	return &usr;
}

scap_groupinfo* sinsp_threadinfo::get_group() {
	auto group = m_inspector->m_usergroup_manager->get_group(get_container_id(), m_gid);
	if(group != nullptr) {
		return group;
	}
	static scap_groupinfo grp = {};
	grp.gid = m_gid;
	strlcpy(grp.name, m_gid == 0 ? "root" : "<NA>", sizeof(grp.name));
	return &grp;
}

scap_userinfo* sinsp_threadinfo::get_loginuser() {
	auto user = m_inspector->m_usergroup_manager->get_user(get_container_id(), m_loginuid);
	if(user != nullptr) {
		return user;
	}
	static scap_userinfo usr{};
	usr.uid = m_loginuid;
	usr.gid = m_gid;
	strlcpy(usr.name, m_loginuid == 0 ? "root" : "<NA>", sizeof(usr.name));
	strlcpy(usr.homedir, m_loginuid == 0 ? "/root" : "<NA>", sizeof(usr.homedir));
	strlcpy(usr.shell, "<NA>", sizeof(usr.shell));
	return &usr;
}

void sinsp_threadinfo::set_args(const char* args, size_t len) {
	if(len > 0 && args[len - 1] == '\0') {
		len--;
	}

	set_args(sinsp_split({args, len}, '\0'));
}

void sinsp_threadinfo::set_args(const std::vector<std::string>& args) {
	m_args = args;
	m_cmd_line = get_comm();
	if(!m_cmd_line.empty()) {
		for(const auto& arg : m_args) {
			m_cmd_line += " ";
			m_cmd_line += arg;
		}
	}
}

void sinsp_threadinfo::set_env(const char* env, size_t len) {
	if(len == SCAP_MAX_ENV_SIZE && m_inspector->large_envs_enabled()) {
		// the environment is possibly truncated, try to read from /proc
		// this may fail for short-lived processes
		if(set_env_from_proc()) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Large environment for process %lu [%s], loaded from /proc",
			                          m_pid,
			                          m_comm.c_str());
			return;
		} else {
			libsinsp_logger()->format(sinsp_logger::SEV_INFO,
			                          "Failed to load environment for process %lu [%s] from /proc, "
			                          "using first %d bytes",
			                          m_pid,
			                          m_comm.c_str(),
			                          SCAP_MAX_ENV_SIZE);
		}
	}

	if(len > 0 && env[len - 1] == '\0') {
		len--;
	}

	m_env = sinsp_split({env, len}, '\0');
}

bool sinsp_threadinfo::set_env_from_proc() {
	std::string environ_path =
	        std::string(scap_get_host_root()) + "/proc/" + std::to_string(m_pid) + "/environ";

	std::ifstream environment(environ_path);
	if(!environment) {
		// failed to read the environment from /proc, work with what we have
		return false;
	}

	m_env.clear();
	while(environment) {
		std::string env;
		getline(environment, env, '\0');
		if(!env.empty()) {
			m_env.emplace_back(env);
		}
	}

	return true;
}

const std::vector<std::string>& sinsp_threadinfo::get_env() {
	if(is_main_thread()) {
		return m_env;
	} else {
		auto mtinfo = get_main_thread();
		if(mtinfo != nullptr) {
			return mtinfo->get_env();
		} else {
			// it should never happen but provide a safe fallback just in case
			// except during sinsp::scap_open() (see sinsp::get_thread()).
			return m_env;
		}
	}
}

// Return value string for the exact environment variable name given
std::string sinsp_threadinfo::get_env(const std::string& name) {
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

std::string sinsp_threadinfo::concatenate_all_env() {
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

void sinsp_threadinfo::set_cgroups(const char* cgroups, size_t len) {
	if(len > 0 && cgroups[len - 1] == '\0') {
		len--;
	}

	set_cgroups(sinsp_split({cgroups, len}, '\0'));
}

void sinsp_threadinfo::set_cgroups(const std::vector<std::string>& cgroups) {
	cgroups_t tmp_cgroups;

	for(const auto& def : cgroups) {
		std::string::size_type eq_pos = def.find("=");
		if(eq_pos == std::string::npos) {
			return;
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
			// blkio has been renamed just `io`
			// in kernel space:
			// https://github.com/torvalds/linux/commit/c165b3e3c7bb68c2ed55a5ac2623f030d01d9567
			subsys = "blkio";
		}

		tmp_cgroups.emplace_back(subsys, cgroup);
	}

	m_cgroups = tmp_cgroups;
}

void sinsp_threadinfo::set_cgroups(const cgroups_t& cgroups) {
	m_cgroups = cgroups;
}

sinsp_threadinfo* sinsp_threadinfo::get_parent_thread() {
	return m_inspector->get_thread_ref(m_ptid, false).get();
}

sinsp_threadinfo* sinsp_threadinfo::get_ancestor_process(uint32_t n) {
	sinsp_threadinfo* mt = get_main_thread();

	for(uint32_t i = 0; i < n; i++) {
		if(mt == nullptr) {
			return nullptr;
		}
		mt = mt->get_parent_thread();
		if(mt == nullptr) {
			return nullptr;
		}
		mt = mt->get_main_thread();
	}

	return mt;
}

sinsp_fdinfo* sinsp_threadinfo::add_fd(int64_t fd, std::unique_ptr<sinsp_fdinfo> fdinfo) {
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL) {
		return NULL;
	}
	auto* res = fd_table_ptr->add(fd, std::move(fdinfo));

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	m_lastevent_fd = fd;

	return res;
}

void sinsp_threadinfo::remove_fd(int64_t fd) {
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL) {
		return;
	}
	fd_table_ptr->erase(fd);
}

bool sinsp_threadinfo::loop_fds(sinsp_fdtable::fdtable_const_visitor_t visitor) {
	sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL) {
		return false;
	}

	return fdt->const_loop(visitor);
}

bool sinsp_threadinfo::is_bound_to_port(uint16_t number) const {
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

bool sinsp_threadinfo::uses_client_port(uint16_t number) const {
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

bool sinsp_threadinfo::is_lastevent_data_valid() const {
	return (m_lastevent_cpuid != (uint16_t)-1);
}

sinsp_threadinfo* sinsp_threadinfo::get_cwd_root() {
	if(!(m_flags & PPM_CL_CLONE_FS)) {
		return this;
	} else {
		return get_main_thread();
	}
}

std::string sinsp_threadinfo::get_cwd() {
	// Ideally we should use get_cwd_root()
	// but scap does not read CLONE_FS from /proc
	// Also glibc and muslc use always
	// CLONE_THREAD|CLONE_FS so let's use
	// get_main_thread() for now
	sinsp_threadinfo* tinfo = get_main_thread();

	if(tinfo) {
		return tinfo->m_cwd;
	} else {
		/// todo(@Andreagit97) not sure we want to return "./" it seems like a valid path
		return "./";
	}
}

void sinsp_threadinfo::update_cwd(std::string_view cwd) {
	sinsp_threadinfo* tinfo = get_main_thread();

	if(tinfo == nullptr) {
		return;
	}

	tinfo->m_cwd = sinsp_utils::concatenate_paths(m_cwd, cwd);

	if(tinfo->m_cwd.empty() || tinfo->m_cwd.back() != '/') {
		tinfo->m_cwd += '/';
	}
}

uint64_t sinsp_threadinfo::get_fd_usage_pct() {
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

sinsp_threadinfo* sinsp_threadinfo::get_oldest_matching_ancestor(
        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
        bool is_virtual_id) {
	int64_t id = get_thread_id(this);
	if(id == -1) {
		// the id is not set
		return nullptr;
	}

	// If we are using a non virtual id or if the id is virtual but we are in the init namespace we
	// can access the thread table directly!
	// if is_virtual_id == false we don't care about the namespace in which we are
	sinsp_threadinfo* leader = nullptr;
	if(!is_virtual_id || !is_in_pid_namespace()) {
		leader = m_inspector->get_thread_ref(id, false).get();
		if(leader != nullptr) {
			return leader;
		}
	}

	// If we are in a pid_namespace we cannot use directly m_sid to access the table
	// since it could be related to a pid namespace.
	sinsp_threadinfo::visitor_func_t visitor = [id, &leader, get_thread_id](sinsp_threadinfo* pt) {
		if(get_thread_id(pt) != id) {
			return false;
		}
		leader = pt;
		return true;
	};

	traverse_parent_state(visitor);
	return leader;
}

std::string sinsp_threadinfo::get_ancestor_field_as_string(
        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
        const std::function<std::string(sinsp_threadinfo*)>& get_field_str,
        bool is_virtual_id) {
	auto ancestor = this->get_oldest_matching_ancestor(get_thread_id, is_virtual_id);
	if(ancestor) {
		return get_field_str(ancestor);
	}
	return "";
}

double sinsp_threadinfo::get_fd_usage_pct_d() {
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

uint64_t sinsp_threadinfo::get_fd_opencount() const {
	auto main_thread = get_main_thread();
	if(main_thread == nullptr) {
		return 0;
	}
	return main_thread->get_fdtable().size();
}

uint64_t sinsp_threadinfo::get_fd_limit() {
	auto main_thread = get_main_thread();
	if(main_thread == nullptr) {
		return 0;
	}
	return main_thread->m_fdlimit;
}

const std::string& sinsp_threadinfo::get_cgroup(const std::string& subsys) const {
	static const std::string notfound = "/";

	for(const auto& it : cgroups()) {
		if(it.first == subsys) {
			return it.second;
		}
	}

	return notfound;
}

bool sinsp_threadinfo::get_cgroup(const std::string& subsys, std::string& cgroup) const {
	for(const auto& it : cgroups()) {
		if(it.first == subsys) {
			cgroup = it.second;
			return true;
		}
	}

	return false;
}

void sinsp_threadinfo::traverse_parent_state(visitor_func_t& visitor) {
	// Use two pointers starting at this, traversing the parent
	// state, at different rates. If they ever equal each other
	// before slow is NULL there's a loop.

	sinsp_threadinfo *slow = this->get_parent_thread(), *fast = slow;

	// Move fast to its parent
	fast = (fast ? fast->get_parent_thread() : fast);

	// The slow pointer must be valid and not have a tid of -1.
	while(slow && slow->m_tid != -1) {
		if(!visitor(slow)) {
			break;
		}

		// Advance slow one step and advance fast two steps
		slow = slow->get_parent_thread();

		// advance fast 2 steps, checking to see if we meet
		// slow after each step.
		for(uint32_t i = 0; i < 2; i++) {
			fast = (fast ? fast->get_parent_thread() : fast);

			// If not at the end but fast == slow or if
			// slow points to itself, there's a loop in
			// the thread state.
			if(slow && (slow == fast || slow->m_tid == slow->m_ptid)) {
				// Note we only log a loop once for a given main thread, to avoid flooding logs.
				if(!m_parent_loop_detected) {
					libsinsp_logger()->log(
					        std::string("Loop in parent thread state detected for pid ") +
					                std::to_string(m_pid) +
					                ". stopped at tid= " + std::to_string(slow->m_tid) +
					                " ptid=" + std::to_string(slow->m_ptid),
					        sinsp_logger::SEV_WARNING);
					m_parent_loop_detected = true;
				}
				return;
			}
		}
	}
}

/* We should never call this method if we don't have children to reparent
 * if we want to save some clock cycles
 */
void sinsp_threadinfo::assign_children_to_reaper(sinsp_threadinfo* reaper) {
	/* We have no children to reparent. */
	if(m_children.size() == 0) {
		return;
	}

	if(reaper == this) {
		throw sinsp_exception("the current process is reaper of itself, this should never happen!");
	}

	auto child = m_children.begin();
	while(child != m_children.end()) {
		/* If the child is not expired we move it to the reaper
		 * and we change its `ptid`.
		 */
		if(!child->expired()) {
			if(reaper == nullptr) {
				/* we set `0` as the parent for all children */
				child->lock()->m_ptid = 0;
			} else {
				/* Add the child to the reaper list */
				reaper->add_child(child->lock());
			}
		}

		/* In any case (expired or not) we remove the child
		 * from the list.
		 */
		child = m_children.erase(child);
	}
	m_not_expired_children = 0;
}

void sinsp_threadinfo::populate_cmdline(std::string& cmdline, const sinsp_threadinfo* tinfo) {
	if(tinfo->m_cmd_line.empty()) {
		cmdline = tinfo->get_comm();
		for(const auto& arg : tinfo->m_args) {
			cmdline += " ";
			cmdline += arg;
		}
	} else {
		cmdline = tinfo->m_cmd_line;
	}
}

std::string sinsp_threadinfo::get_path_for_dir_fd(int64_t dir_fd) {
	sinsp_fdinfo* dir_fdinfo = get_fd(dir_fd);
	if(!dir_fdinfo || dir_fdinfo->m_name.empty()) {
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
	return dir_fdinfo->m_name;
}

size_t sinsp_threadinfo::args_len() const {
	return strvec_len(m_args);
}

size_t sinsp_threadinfo::env_len() const {
	return strvec_len(m_env);
}

void sinsp_threadinfo::args_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const {
	return strvec_to_iovec(m_args, iov, iovcnt, rem);
}

void sinsp_threadinfo::env_to_iovec(struct iovec** iov, int* iovcnt, std::string& rem) const {
	return strvec_to_iovec(m_env, iov, iovcnt, rem);
}

// Set the provided iovec to the string in str, if it will fit. If it
// won't, copy the portion that will fit to rem and set the iovec to
// rem. Updates alen with the new total length and possibly sets rem
// to any truncated string.
void sinsp_threadinfo::add_to_iovec(const std::string& str,
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
void sinsp_threadinfo::cgroups_to_iovec(struct iovec** iov,
                                        int* iovcnt,
                                        std::string& rem,
                                        const cgroups_t& cgroups) const {
	uint32_t alen = SCAP_MAX_ARGS_SIZE;
	static const std::string eq = "=";

	// We allocate an iovec big enough to hold all the cgroups and
	// intermediate '=' signs. Based on alen, we might not use all
	// of the iovec.
	*iov = (struct iovec*)malloc((3 * cgroups.size()) * sizeof(struct iovec));
	if(iov == NULL) {
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

size_t sinsp_threadinfo::strvec_len(const std::vector<std::string>& strs) const {
	size_t totlen = 0;

	for(auto& str : strs) {
		totlen += str.size();
		totlen++;  // Trailing NULL
	}

	return totlen;
}

// iov will be allocated and must be freed. rem is used to hold a
// possibly truncated final argument.
void sinsp_threadinfo::strvec_to_iovec(const std::vector<std::string>& strs,
                                       struct iovec** iov,
                                       int* iovcnt,
                                       std::string& rem) const {
	uint32_t alen = SCAP_MAX_ARGS_SIZE;

	// We allocate an iovec big enough to hold all the entries in
	// strs. Based on alen, we might not use all of the iovec.
	*iov = (struct iovec*)malloc(strs.size() * sizeof(struct iovec));
	if(iov == NULL) {
		throw sinsp_exception("memory allocation error in sinsp_threadinfo::strvec_to_iovec.");
	}

	*iovcnt = 0;

	for(auto it = strs.begin(); it != strs.end() && alen > 0; ++it) {
		add_to_iovec(*it, true, (*iov)[(*iovcnt)++], alen, rem);
	}
}

void sinsp_threadinfo::set_exepath(std::string&& exepath) {
	constexpr char suffix[] = " (deleted)";
	constexpr size_t suffix_len = sizeof(suffix) - 1;  // Exclude null terminator

	m_exepath = exepath;
	if(m_exepath.size() > suffix_len &&
	   m_exepath.compare(m_exepath.size() - suffix_len, suffix_len, suffix) == 0) {
		m_exepath.resize(m_exepath.size() - suffix_len);
	}
}
