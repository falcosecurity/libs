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

constexpr static const char* s_thread_table_name = "threads";

extern sinsp_evttables g_infotables;

static void copy_ipv6_address(uint32_t* dest, uint32_t* src)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_threadinfo implementation
///////////////////////////////////////////////////////////////////////////////

sinsp_threadinfo::sinsp_threadinfo(sinsp* inspector, std::shared_ptr<libsinsp::state::dynamic_struct::field_infos> dyn_fields):
	table_entry(dyn_fields),
	m_cgroups(new cgroups_t),
	m_inspector(inspector),
	m_fdtable(inspector),
	m_args_table_adapter("args", m_args),
	m_env_table_adapter("env", m_env)
{
	init();
}

libsinsp::state::static_struct::field_infos sinsp_threadinfo::static_fields() const
{
	libsinsp::state::static_struct::field_infos ret;
	// todo(jasondellaluce): support missing fields that are vectors, maps, or sub-tables
	define_static_field(ret, this, m_tid, "tid");
	define_static_field(ret, this, m_pid, "pid");
	define_static_field(ret, this, m_ptid, "ptid");
	define_static_field(ret, this, m_reaper_tid, "reaper_tid");
	define_static_field(ret, this, m_sid, "sid");
	define_static_field(ret, this, m_comm, "comm");
	define_static_field(ret, this, m_exe, "exe");
	define_static_field(ret, this, m_exepath, "exe_path");
	define_static_field(ret, this, m_exe_writable, "exe_writable");
	define_static_field(ret, this, m_exe_upper_layer, "exe_upper_layer");
	define_static_field(ret, this, m_exe_from_memfd, "exe_from_memfd");
	define_static_field(ret, this, m_args_table_adapter.table_ptr(), "args", true);
	define_static_field(ret, this, m_env_table_adapter.table_ptr(), "env", true);
	// m_cgroups
	define_static_field(ret, this, m_container_id, "container_id");
	define_static_field(ret, this, m_flags, "flags");
	define_static_field(ret, this, m_fdlimit, "fd_limit");
	// m_user
	// m_loginuser
	// m_group
	// m_cap_permitted
	// m_cap_effective
	// m_cap_inheritable
	define_static_field(ret, this, m_exe_ino, "exe_ino");
	define_static_field(ret, this, m_exe_ino_ctime, "exe_ino_ctime");
	define_static_field(ret, this, m_exe_ino_mtime, "exe_ino_mtime");
	// m_exe_ino_ctime_duration_clone_ts
	// m_exe_ino_ctime_duration_pidns_start
	// m_vmsize_kb
	// m_vmrss_kb
	// m_vmswap_kb
	// m_pfmajor
	// m_pfminor
	define_static_field(ret, this, m_vtid, "vtid");
	define_static_field(ret, this, m_vpid, "vpid");
	define_static_field(ret, this, m_vpgid, "vpgid");
	define_static_field(ret, this, m_pidns_init_start_ts, "pidns_init_start_ts");
	define_static_field(ret, this, m_root, "root");
	// m_program_hash
	// m_program_hash_scripts
	define_static_field(ret, this, m_tty, "tty");
	// m_category
	// m_clone_ts
	// m_lastexec_ts
	// m_latency
	define_static_field(ret, this, m_fdtable.table_ptr(), "file_descriptors", true);
	define_static_field(ret, this, m_cwd, "cwd", true);
	// m_parent_loop_detected
	return ret;
}

void sinsp_threadinfo::init()
{
	m_pid = (uint64_t) - 1LL;
	m_sid = (uint64_t) - 1LL;
	m_ptid = (uint64_t) - 1LL;
	m_vpgid = (uint64_t) - 1LL;
	set_lastevent_data_validity(false);
	m_reaper_tid = - 1;
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
	m_program_hash = 0;
	m_program_hash_scripts = 0;
	m_lastevent_data = NULL;
	m_parent_loop_detected = false;
	m_tty = 0;
	m_category = CAT_NONE;
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
	m_exe_from_memfd = false;
}

sinsp_threadinfo::~sinsp_threadinfo()
{
	if(m_lastevent_data)
	{
		free(m_lastevent_data);
	}
}

void sinsp_threadinfo::fix_sockets_coming_from_proc()
{
	m_fdtable.loop([this](int64_t fd, sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(m_inspector->m_thread_manager->m_server_ports.find(fdi.m_sockinfo.m_ipv4info.m_fields.m_sport) !=
				m_inspector->m_thread_manager->m_server_ports.end())
			{
				uint32_t tip;
				uint16_t tport;

				tip = fdi.m_sockinfo.m_ipv4info.m_fields.m_sip;
				tport = fdi.m_sockinfo.m_ipv4info.m_fields.m_sport;

				fdi.m_sockinfo.m_ipv4info.m_fields.m_sip = fdi.m_sockinfo.m_ipv4info.m_fields.m_dip;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_dip = tip;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_sport = fdi.m_sockinfo.m_ipv4info.m_fields.m_dport;
				fdi.m_sockinfo.m_ipv4info.m_fields.m_dport = tport;

				fdi.m_name = ipv4tuple_to_string(&fdi.m_sockinfo.m_ipv4info, m_inspector->is_hostname_and_port_resolution_enabled());

				fdi.set_role_server();
			}
			else
			{
				fdi.set_role_client();
			}
		}
		return true;
	});
}

#define STR_AS_NUM_JAVA 0x6176616a
#define STR_AS_NUM_RUBY 0x79627572
#define STR_AS_NUM_PERL 0x6c726570
#define STR_AS_NUM_NODE 0x65646f6e

#define MAX_PROG_HASH_LEN 1024

void sinsp_threadinfo::compute_program_hash()
{
	auto curr_hash = std::hash<std::string>()(m_exe);
	hash_combine(curr_hash, m_container_id);
	auto rem_len = MAX_PROG_HASH_LEN - (m_exe.size() + m_container_id.size());

	//
	// By default, the scripts hash is just exe+container
	//
	m_program_hash_scripts = curr_hash;

	//
	// The program hash includes the arguments as well
	//
	for (auto arg = m_args.begin(); arg != m_args.end() && rem_len > 0; ++arg)
	{
		if (arg->size() >= rem_len)
		{
			auto partial_str = arg->substr(0, rem_len);
			hash_combine(curr_hash, partial_str);
			break;
		}

		hash_combine(curr_hash, *arg);
		rem_len -= arg->size();
	}
	m_program_hash = curr_hash;

	//
	// For some specific processes (essentially the scripting languages)
	// we include the arguments in the scripts hash as well
	//
	if(m_comm.size() == 4)
	{
		uint32_t ncomm = *(uint32_t*)m_comm.c_str();

		if(ncomm == STR_AS_NUM_JAVA || ncomm == STR_AS_NUM_RUBY ||
			ncomm == STR_AS_NUM_PERL || ncomm == STR_AS_NUM_NODE)
		{
			m_program_hash_scripts = m_program_hash;
		}
	}
	else if(m_comm.size() >= 6)
	{
		if(m_comm.substr(0, 6) == "python")
		{
			m_program_hash_scripts = m_program_hash;
		}
	}
}

void sinsp_threadinfo::add_fd_from_scap(scap_fdinfo *fdi)
{
	auto newfdi = m_inspector->build_fdinfo();
	bool do_add = true;

	newfdi->m_type = fdi->type;
	newfdi->m_openflags = 0;
	newfdi->m_type = fdi->type;
	newfdi->m_flags = sinsp_fdinfo::FLAGS_FROM_PROC;
	newfdi->m_ino = fdi->ino;
	newfdi->m_fd = fdi->fd;

	switch(newfdi->m_type)
	{
	case SCAP_FD_IPV4_SOCK:
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
		if(fdi->info.ipv4info.l4proto == SCAP_L4_TCP)
		{
			newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
		}
		m_inspector->get_ifaddr_list().update_fd(*newfdi);
		newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->is_hostname_and_port_resolution_enabled());
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		newfdi->m_sockinfo.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
		newfdi->m_name = ipv4serveraddr_to_string(&newfdi->m_sockinfo.m_ipv4serverinfo, m_inspector->is_hostname_and_port_resolution_enabled());

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv4serverinfo.m_port);

		break;
	case SCAP_FD_IPV6_SOCK:
		if(sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.sip) &&
			sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.dip))
		{
			//
			// This is an IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses).
			// Convert it into the IPv4 representation.
			//
			newfdi->m_type = SCAP_FD_IPV4_SOCK;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv6info.sip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv6info.dip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			if(fdi->info.ipv6info.l4proto == SCAP_L4_TCP)
			{
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			m_inspector->get_ifaddr_list().update_fd(*newfdi);
			newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->is_hostname_and_port_resolution_enabled());
		}
		else
		{
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b, fdi->info.ipv6info.sip);
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b, fdi->info.ipv6info.dip);
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			if(fdi->info.ipv6info.l4proto == SCAP_L4_TCP)
			{
				newfdi->m_flags |= sinsp_fdinfo::FLAGS_SOCKET_CONNECTED;
			}
			newfdi->m_name = ipv6tuple_to_string(&newfdi->m_sockinfo.m_ipv6info, m_inspector->is_hostname_and_port_resolution_enabled());
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(newfdi->m_sockinfo.m_ipv6serverinfo.m_ip.m_b, fdi->info.ipv6serverinfo.ip);
		newfdi->m_sockinfo.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
		newfdi->m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi->info.ipv6serverinfo.l4proto;
		newfdi->m_name = ipv6serveraddr_to_string(&newfdi->m_sockinfo.m_ipv6serverinfo, m_inspector->is_hostname_and_port_resolution_enabled());

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv6serverinfo.m_port);

		break;
	case SCAP_FD_UNIX_SOCK:
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_source = fdi->info.unix_socket_info.source;
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_dest = fdi->info.unix_socket_info.destination;
		newfdi->m_name = fdi->info.unix_socket_info.fname;
		if(newfdi->m_name.empty())
		{
			newfdi->set_role_client();
		}
		else
		{
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
	if(!do_add)
	{
		return;
	}

	auto addedfdi = m_fdtable.add(fdi->fd, std::move(newfdi));
	if(m_inspector->m_filter != nullptr && m_inspector->is_capture())
	{
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

		if(m_inspector->m_filter->run(&tevt))
		{
			// we mark the thread info as non-filterable due to one event
			// using one of its file descriptor has passed the filter
			m_filtered_out = false;
		}
		else
		{
			// we can't say if the thread info for this fd is filterable or not,
			// but we can mark the given file descriptor as filterable. This flag
			// will prevent the fd info from being written in captures.
			fdi->type = SCAP_FD_UNINITIALIZED;
		}

		tevt.get_tinfo()->m_lastevent_fd = tlefd;
		m_lastevent_data = NULL;
	}
}

void sinsp_threadinfo::init(scap_threadinfo* pi)
{
	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_ptid = pi->ptid;
	m_sid = pi->sid;
	m_vpgid = pi->vpgid;

	m_comm = pi->comm;
	m_exe = pi->exe;
	/* The exepath is extracted from `/proc/pid/exe`. */
	m_exepath = pi->exepath;
	m_exe_writable = pi->exe_writable;
	m_exe_upper_layer = pi->exe_upper_layer;
	m_exe_from_memfd = pi->exe_from_memfd;

	/* We cannot obtain the reaper_tid from a /proc scan */
	m_reaper_tid = -1;
	m_not_expired_children = 0;

	set_args(pi->args, pi->args_len);
	if(is_main_thread())
	{
		set_env(pi->env, pi->env_len);
		update_cwd({pi->cwd});
	}
	m_flags |= pi->flags;
	m_flags |= PPM_CL_ACTIVE; // Assume that all the threads coming from /proc are real, active threads
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
	m_category = CAT_NONE;

	set_cgroups(pi->cgroups.path, pi->cgroups.len);
	m_root = pi->root;
	ASSERT(m_inspector);
	m_inspector->m_container_manager.resolve_container(this, m_inspector->is_live() || m_inspector->is_syscall_plugin());

	set_group(pi->gid);
	set_user(pi->uid);
	set_loginuser((uint32_t)pi->loginuid);
}

void sinsp_threadinfo::set_user(uint32_t uid)
{
	scap_userinfo *user = m_inspector->m_usergroup_manager.get_user(m_container_id, uid);
	if (!user)
	{
		auto notify = m_inspector->is_live() || m_inspector->is_syscall_plugin();
		user = m_inspector->m_usergroup_manager.add_user(m_container_id, m_pid, uid, m_group.gid(), {}, {}, {}, notify);
	}

	if (user)
	{
		m_user.set_uid(user->uid);
		m_user.set_gid(m_group.gid());

		if (m_inspector->is_user_details_enabled())
		{
			m_user.set_name(user->name, strnlen(user->name, MAX_CREDENTIALS_STR_LEN));
			m_user.set_homedir(user->homedir, strnlen(user->homedir, MAX_CREDENTIALS_STR_LEN));
			m_user.set_shell(user->shell, strnlen(user->shell, MAX_CREDENTIALS_STR_LEN));
		}
	}
	else
	{
		// No need to set name/homedir/shell, the default values from
		// sinsp_userinfo are going to be used.
		m_user.set_uid(uid);
		m_user.set_gid(m_group.gid());
	}
}

void sinsp_threadinfo::set_group(uint32_t gid)
{
	scap_groupinfo *group = m_inspector->m_usergroup_manager.get_group(m_container_id, gid);
	if (!group)
	{
		auto notify = m_inspector->is_live() || m_inspector->is_syscall_plugin();
		group = m_inspector->m_usergroup_manager.add_group(m_container_id, m_pid, gid, {}, notify);
	}
	if (group)
	{
		m_group.set_gid(group->gid);

		if (m_inspector->is_user_details_enabled())
		{
			m_group.set_name(group->name, strnlen(group->name, MAX_CREDENTIALS_STR_LEN));
		}
	}
	else
	{
		// No need to set name/homedir/shell, the default values from
		// sinsp_userinfo are going to be used.
		m_group.set_gid(gid);
	}
	m_user.set_gid(m_group.gid());
}

void sinsp_threadinfo::set_loginuser(uint32_t loginuid)
{
	scap_userinfo *login_user = m_inspector->m_usergroup_manager.get_user(m_container_id, loginuid);

	if (login_user)
	{
		m_loginuser.set_uid(login_user->uid);
		m_loginuser.set_gid(m_group.gid());

		if (m_inspector->is_user_details_enabled())
		{
			m_loginuser.set_name(login_user->name, strnlen(login_user->name, MAX_CREDENTIALS_STR_LEN));
			m_loginuser.set_homedir(login_user->homedir, strnlen(login_user->homedir, MAX_CREDENTIALS_STR_LEN));
			m_loginuser.set_shell(login_user->shell, strnlen(login_user->shell, MAX_CREDENTIALS_STR_LEN));
		}
	}
	else
	{
		// No need to set name/homedir/shell, the default values from
		// sinsp_userinfo are going to be used.
		m_loginuser.set_uid(loginuid);
		m_loginuser.set_gid(m_group.gid());
	}
}

sinsp_threadinfo::cgroups_t& sinsp_threadinfo::cgroups() const
{
	if(m_cgroups)
	{
		return *m_cgroups;
	}

	static cgroups_t empty;
	return empty;
}

std::string sinsp_threadinfo::get_comm() const
{
	return m_comm;
}

std::string sinsp_threadinfo::get_exe() const
{
	return m_exe;
}

std::string sinsp_threadinfo::get_exepath() const
{
	return m_exepath;
}

void sinsp_threadinfo::set_args(const char* args, size_t len)
{
	set_args(sinsp_split(args, len, '\0'));
}

void sinsp_threadinfo::set_args(std::vector<std::string> args)
{
	m_args = args;
}

void sinsp_threadinfo::set_env(const char* env, size_t len)
{
	if (len == SCAP_MAX_ENV_SIZE && m_inspector->large_envs_enabled())
	{
		// the environment is possibly truncated, try to read from /proc
		// this may fail for short-lived processes
		if (set_env_from_proc())
		{
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "Large environment for process %lu [%s], loaded from /proc", m_pid, m_comm.c_str());
			return;
		} else {
			libsinsp_logger()->format(sinsp_logger::SEV_INFO, "Failed to load environment for process %lu [%s] from /proc, using first %d bytes", m_pid, m_comm.c_str(), SCAP_MAX_ENV_SIZE);
		}
	}

	m_env = sinsp_split(env, len, '\0');
}

bool sinsp_threadinfo::set_env_from_proc() {
	std::string environ_path = std::string(scap_get_host_root()) + "/proc/" + std::to_string(m_pid) + "/environ";

	std::ifstream environment(environ_path);
	if (!environment)
	{
		// failed to read the environment from /proc, work with what we have
		return false;
	}

	m_env.clear();
	while (environment) {
		std::string env;
		getline(environment, env, '\0');
		if (!env.empty())
		{
			m_env.emplace_back(env);
		}
	}

	return true;
}

const std::vector<std::string>& sinsp_threadinfo::get_env()
{
	if(is_main_thread())
	{
		return m_env;
	}
	else
	{
		auto mtinfo = get_main_thread();
		if(mtinfo != nullptr)
		{
			return mtinfo->get_env();
		}
		else
		{
			// it should never happen but provide a safe fallback just in case
			// except during sinsp::scap_open() (see sinsp::get_thread()).
			return m_env;
		}
	}
}

// Return value string for the exact environment variable name given
std::string sinsp_threadinfo::get_env(const std::string& name)
{
	size_t nlen = name.length();
	for(const auto& env_var : get_env())
	{
		if((env_var.length() > (nlen + 1)) && (env_var[nlen] == '=') &&
			!env_var.compare(0, nlen, name))
		{
			// Stripping spaces, not sure if we really should or need to
			size_t first = env_var.find_first_not_of(' ', nlen + 1);
			if (first == std::string::npos)
				return "";
			size_t last = env_var.find_last_not_of(' ');

			return env_var.substr(first, last - first + 1);
		}
	}

	return "";
}

std::string sinsp_threadinfo::concatenate_all_env()
{
	const auto& all_env = get_env();
	if(all_env.size() == 0)
	{
		return "";
	}

	// Here we have at least one env so we can pop the last character at the end of the loop.
	std::string concatenate_env;
	for(const auto& env_var : all_env)
	{
		concatenate_env += env_var;
		concatenate_env += ' ';
	}
	concatenate_env.pop_back();
	return concatenate_env;
}

void sinsp_threadinfo::set_cgroups(const char* cgroups, size_t len)
{
	set_cgroups(sinsp_split(cgroups, len, '\0'));
}

void sinsp_threadinfo::set_cgroups(std::vector<std::string> cgroups)
{
	decltype(m_cgroups) tmp_cgroups(new cgroups_t);

	for( auto &def : cgroups)
	{
		std::string::size_type eq_pos = def.find("=");
		if (eq_pos == std::string::npos)
		{
			return;
		}

		std::string subsys = def.substr(0, eq_pos);
		std::string cgroup = def.substr(eq_pos + 1);

		size_t pos = subsys.find("_cgroup");
		if(pos != std::string::npos)
		{
			subsys.erase(pos, sizeof("_cgroup") - 1);
		}

		if(subsys == "perf")
		{
			subsys = "perf_event";
		}
		else if(subsys == "mem")
		{
			subsys = "memory";
		}
		else if(subsys == "io")
		{
			// blkio has been renamed just `io`
			// in kernel space:
			// https://github.com/torvalds/linux/commit/c165b3e3c7bb68c2ed55a5ac2623f030d01d9567
			subsys = "blkio";
		}

		tmp_cgroups->push_back(std::make_pair(subsys, cgroup));
	}

	m_cgroups.swap(tmp_cgroups);
}

sinsp_threadinfo* sinsp_threadinfo::get_parent_thread()
{
	return m_inspector->get_thread_ref(m_ptid, false).get();
}

sinsp_fdinfo* sinsp_threadinfo::add_fd(int64_t fd, std::unique_ptr<sinsp_fdinfo> fdinfo)
{
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL)
	{
		ASSERT(false);
		return NULL;
	}
	auto* res = fd_table_ptr->add(fd, std::move(fdinfo));

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	m_lastevent_fd = fd;

	return res;
}

void sinsp_threadinfo::remove_fd(int64_t fd)
{
	sinsp_fdtable* fd_table_ptr = get_fd_table();
	if(fd_table_ptr == NULL)
	{
		ASSERT(false);
		return;
	}
	fd_table_ptr->erase(fd);
}

bool sinsp_threadinfo::loop_fds(sinsp_fdtable::fdtable_const_visitor_t visitor)
{
	sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL)
	{
		ASSERT(false);
		return false;
	}

	return fdt->const_loop(visitor);
}

bool sinsp_threadinfo::is_bound_to_port(uint16_t number) const
{
	const sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL)
	{
		ASSERT(false);
		return false;
	}

	bool ret = false;
	fdt->const_loop([&](int64_t fd, const sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(fdi.m_sockinfo.m_ipv4info.m_fields.m_dport == number)
			{
				// set result and break out of the loop
				ret = true;
				return false;
			}
		}
		else if(fdi.m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			if(fdi.m_sockinfo.m_ipv4serverinfo.m_port == number)
			{
				// set result and break out of the loop
				ret = true;
				return false;
			}
		}
		return true;
	});

	return ret;
}

bool sinsp_threadinfo::uses_client_port(uint16_t number) const
{
	const sinsp_fdtable* fdt = get_fd_table();
	if(fdt == NULL)
	{
		ASSERT(false);
		return false;
	}

	bool ret = false;
	fdt->const_loop([&](int64_t fd, const sinsp_fdinfo& fdi) {
		if(fdi.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(fdi.m_sockinfo.m_ipv4info.m_fields.m_sport == number)
			{
				// set result and break out of the loop
				ret = true;
				return false;
			}
		}
		return true;
	});

	return ret;
}

bool sinsp_threadinfo::is_lastevent_data_valid() const
{
	return (m_lastevent_cpuid != (uint16_t) - 1);
}

sinsp_threadinfo* sinsp_threadinfo::get_cwd_root()
{
	if(!(m_flags & PPM_CL_CLONE_FS))
	{
		return this;
	}
	else
	{
		return get_main_thread();
	}
}

std::string sinsp_threadinfo::get_cwd()
{
	// Ideally we should use get_cwd_root()
	// but scap does not read CLONE_FS from /proc
	// Also glibc and muslc use always
	// CLONE_THREAD|CLONE_FS so let's use
	// get_main_thread() for now
	sinsp_threadinfo* tinfo = get_main_thread();

	if(tinfo)
	{
		return tinfo->m_cwd;
	}
	else
	{
		///todo(@Andreagit97) not sure we want to return "./" it seems like a valid path
		return "./";
	}
}

void sinsp_threadinfo::update_cwd(std::string_view cwd)
{
	sinsp_threadinfo* tinfo = get_main_thread();

	if (tinfo == nullptr)
	{
		return;
	}

	tinfo->m_cwd = sinsp_utils::concatenate_paths(m_cwd, cwd);

	if(tinfo->m_cwd.empty() || tinfo->m_cwd.back() != '/')
	{
		tinfo->m_cwd += '/';
	}
}

uint64_t sinsp_threadinfo::get_fd_usage_pct()
{
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0)
	{
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t) fdlimit);
		if(fd_opencount <= (uint64_t) fdlimit)
		{
			return (fd_opencount * 100) / fdlimit;
		}
		else
		{
			return 100;
		}
	}
	else
	{
		return 0;
	}
}

double sinsp_threadinfo::get_fd_usage_pct_d()
{
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0)
	{
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t) fdlimit);
		if(fd_opencount <= (uint64_t) fdlimit)
		{
			return ((double)fd_opencount * 100) / fdlimit;
		}
		else
		{
			return 100;
		}
	}
	else
	{
		return 0;
	}
}

uint64_t sinsp_threadinfo::get_fd_opencount() const
{
	auto main_thread = get_main_thread();
	if(main_thread == nullptr)
	{
		return 0;
	}
	return main_thread->get_fdtable().size();
}

uint64_t sinsp_threadinfo::get_fd_limit()
{
	auto main_thread = get_main_thread();
	if(main_thread == nullptr)
	{
		return 0;
	}
	return main_thread->m_fdlimit;
}

const std::string& sinsp_threadinfo::get_cgroup(const std::string& subsys) const
{
	static const std::string notfound = "/";

	for(const auto& it : cgroups())
	{
		if(it.first == subsys)
		{
			return it.second;
		}
	}

	return notfound;
}

bool sinsp_threadinfo::get_cgroup(const std::string& subsys, std::string& cgroup) const
{
	for(const auto& it : cgroups())
	{
		if(it.first == subsys)
		{
			cgroup = it.second;
			return true;
		}
	}

	return false;
}

void sinsp_threadinfo::traverse_parent_state(visitor_func_t &visitor)
{
	// Use two pointers starting at this, traversing the parent
	// state, at different rates. If they ever equal each other
	// before slow is NULL there's a loop.

	sinsp_threadinfo *slow=this->get_parent_thread(), *fast=slow;

	// Move fast to its parent
	fast = (fast ? fast->get_parent_thread() : fast);

	// The slow pointer must be valid and not have a tid of -1.
	while(slow && slow->m_tid != -1)
	{
		if(!visitor(slow))
		{
			break;
		}

		// Advance slow one step and advance fast two steps
		slow = slow->get_parent_thread();

		// advance fast 2 steps, checking to see if we meet
		// slow after each step.
		for (uint32_t i = 0; i < 2; i++) {
			fast = (fast ? fast->get_parent_thread() : fast);

			// If not at the end but fast == slow or if
			// slow points to itself, there's a loop in
			// the thread state.
			if(slow && (slow == fast ||
				    slow->m_tid == slow->m_ptid))
			{
				// Note we only log a loop once for a given main thread, to avoid flooding logs.
				if(!m_parent_loop_detected)
				{
					libsinsp_logger()->log(std::string("Loop in parent thread state detected for pid ") +
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
void sinsp_threadinfo::assign_children_to_reaper(sinsp_threadinfo* reaper)
{
	/* We have no children to reparent. */
	if(m_children.size() == 0)
	{
		return;
	}

	if(reaper == this)
	{
		throw sinsp_exception("the current process is reaper of itself, this should never happen!");
	}

	auto child = m_children.begin();
	while(child != m_children.end())
	{
		/* If the child is not expired we move it to the reaper
		 * and we change its `ptid`.
		 */
		if(!child->expired())
		{
			if(reaper == nullptr)
			{
				/* we set `0` as the parent for all children */
				child->lock()->m_ptid = 0;
			}
			else
			{
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

void sinsp_threadinfo::populate_cmdline(std::string &cmdline, const sinsp_threadinfo *tinfo)
{
	cmdline = tinfo->get_comm();

	for (const auto& arg : tinfo->m_args)
	{
		cmdline += " ";
		cmdline += arg;
	}
}

bool sinsp_threadinfo::is_health_probe() const
{
	return (m_category == sinsp_threadinfo::CAT_HEALTHCHECK ||
		m_category == sinsp_threadinfo::CAT_LIVENESS_PROBE ||
	        m_category == sinsp_threadinfo::CAT_READINESS_PROBE);
}

std::string sinsp_threadinfo::get_path_for_dir_fd(int64_t dir_fd)
{
	sinsp_fdinfo* dir_fdinfo = get_fd(dir_fd);
	if (!dir_fdinfo || dir_fdinfo->m_name.empty())
	{
#ifndef _WIN32 // we will have to implement this for Windows
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
		if (ret < 0)
		{
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
#endif // _WIN32
	}
	return dir_fdinfo->m_name;
}

size_t sinsp_threadinfo::args_len() const
{
	return strvec_len(m_args);
}

size_t sinsp_threadinfo::env_len() const
{
	return strvec_len(m_env);
}

void sinsp_threadinfo::args_to_iovec(struct iovec **iov, int *iovcnt,
				     std::string &rem) const
{
	return strvec_to_iovec(m_args,
			       iov, iovcnt,
			       rem);
}

void sinsp_threadinfo::env_to_iovec(struct iovec **iov, int *iovcnt,
				    std::string &rem) const
{
	return strvec_to_iovec(m_env,
			       iov, iovcnt,
			       rem);
}

// Set the provided iovec to the string in str, if it will fit. If it
// won't, copy the portion that will fit to rem and set the iovec to
// rem. Updates alen with the new total length and possibly sets rem
// to any truncated string.
void sinsp_threadinfo::add_to_iovec(const std::string &str,
				    const bool include_trailing_null,
				    struct iovec &iov,
				    uint32_t &alen,
				    std::string &rem) const
{
	uint32_t len = str.size() + (include_trailing_null ? 1 : 0);
	const char *buf = str.c_str();

	if(len > alen)
	{
		// The entire string won't fit. Use rem to hold a
		// truncated copy
		rem = str.substr(0, alen-1);
		buf = rem.c_str();
		len = alen;
	}

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	alen -= len;
}

// iov will be allocated and must be freed. rem is used to hold a
// possibly truncated final argument.
void sinsp_threadinfo::cgroups_to_iovec(struct iovec **iov, int *iovcnt,
				       std::string &rem, const cgroups_t& cgroups) const
{
	uint32_t alen = SCAP_MAX_ARGS_SIZE;
	static const std::string eq = "=";

	// We allocate an iovec big enough to hold all the cgroups and
	// intermediate '=' signs. Based on alen, we might not use all
	// of the iovec.
	*iov = (struct iovec *) malloc((3 * cgroups.size()) * sizeof(struct iovec));
	if(iov == NULL)
	{
		throw sinsp_exception("memory allocation error in sinsp_threadinfo::cgroups_to_iovec.");
	}

	*iovcnt = 0;

	for(auto it = cgroups.begin(); it != cgroups.end() && alen > 0; ++it)
	{
		add_to_iovec(it->first, false, (*iov)[(*iovcnt)++], alen, rem);
		if(alen > 0)
		{
			add_to_iovec(eq, false, (*iov)[(*iovcnt)++], alen, rem);
		}

		if(alen > 0)
		{
			add_to_iovec(it->second, true, (*iov)[(*iovcnt)++], alen, rem);
		}
	}
}

size_t sinsp_threadinfo::strvec_len(const std::vector<std::string> &strs) const
{
	size_t totlen = 0;

	for(auto &str : strs)
	{
		totlen += str.size();
		totlen++; // Trailing NULL
	}

	return totlen;
}

// iov will be allocated and must be freed. rem is used to hold a
// possibly truncated final argument.
void sinsp_threadinfo::strvec_to_iovec(const std::vector<std::string> &strs,
				       struct iovec **iov, int *iovcnt,
				       std::string &rem) const
{
	uint32_t alen = SCAP_MAX_ARGS_SIZE;

	// We allocate an iovec big enough to hold all the entries in
	// strs. Based on alen, we might not use all of the iovec.
	*iov = (struct iovec *) malloc(strs.size() * sizeof(struct iovec));
	if(iov == NULL)
	{
		throw sinsp_exception("memory allocation error in sinsp_threadinfo::strvec_to_iovec.");
	}

	*iovcnt = 0;

	for(auto it = strs.begin(); it != strs.end() && alen > 0; ++it)
	{
		add_to_iovec(*it, true, (*iov)[(*iovcnt)++], alen, rem);
	}
}

static void fd_to_scap(scap_fdinfo *dst, sinsp_fdinfo* src)
{
	dst->type = src->m_type;
	dst->ino = src->m_ino;
	dst->fd = src->m_fd;

	switch(dst->type)
	{
	case SCAP_FD_IPV4_SOCK:
		dst->info.ipv4info.sip = src->m_sockinfo.m_ipv4info.m_fields.m_sip;
		dst->info.ipv4info.dip = src->m_sockinfo.m_ipv4info.m_fields.m_dip;
		dst->info.ipv4info.sport = src->m_sockinfo.m_ipv4info.m_fields.m_sport;
		dst->info.ipv4info.dport = src->m_sockinfo.m_ipv4info.m_fields.m_dport;
		dst->info.ipv4info.l4proto = src->m_sockinfo.m_ipv4info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		dst->info.ipv4serverinfo.ip = src->m_sockinfo.m_ipv4serverinfo.m_ip;
		dst->info.ipv4serverinfo.port = src->m_sockinfo.m_ipv4serverinfo.m_port;
		dst->info.ipv4serverinfo.l4proto = src->m_sockinfo.m_ipv4serverinfo.m_l4proto;
		break;
	case SCAP_FD_IPV6_SOCK:
		copy_ipv6_address(dst->info.ipv6info.sip, src->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b);
		copy_ipv6_address(dst->info.ipv6info.dip, src->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b);
		dst->info.ipv6info.sport = src->m_sockinfo.m_ipv6info.m_fields.m_sport;
		dst->info.ipv6info.dport = src->m_sockinfo.m_ipv6info.m_fields.m_dport;
		dst->info.ipv6info.l4proto = src->m_sockinfo.m_ipv6info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(dst->info.ipv6serverinfo.ip, src->m_sockinfo.m_ipv6serverinfo.m_ip.m_b);
		dst->info.ipv6serverinfo.port = src->m_sockinfo.m_ipv6serverinfo.m_port;
		dst->info.ipv6serverinfo.l4proto = src->m_sockinfo.m_ipv6serverinfo.m_l4proto;
		break;
	case SCAP_FD_UNIX_SOCK:
		dst->info.unix_socket_info.source = src->m_sockinfo.m_unixinfo.m_fields.m_source;
		dst->info.unix_socket_info.destination = src->m_sockinfo.m_unixinfo.m_fields.m_dest;
		strlcpy(dst->info.unix_socket_info.fname, src->m_name.c_str(), sizeof(dst->info.unix_socket_info.fname));
		break;
	case SCAP_FD_FILE_V2:
		dst->info.regularinfo.open_flags = src->m_openflags;
		strlcpy(dst->info.regularinfo.fname, src->m_name.c_str(), sizeof(dst->info.regularinfo.fname));
		dst->info.regularinfo.dev = src->m_dev;
		dst->info.regularinfo.mount_id = src->m_mount_id;
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
		strlcpy(dst->info.fname, src->m_name.c_str(), sizeof(dst->info.fname));
		break;
	default:
		ASSERT(false);
		break;
	}
}

static const auto s_threadinfo_static_fields = sinsp_threadinfo().static_fields();

///////////////////////////////////////////////////////////////////////////////
// sinsp_thread_manager implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_thread_manager::sinsp_thread_manager(sinsp* inspector)
	: table(s_thread_table_name, &s_threadinfo_static_fields),
	  m_max_thread_table_size(m_thread_table_default_size),
	  m_fdtable_dyn_fields(std::make_shared<libsinsp::state::dynamic_struct::field_infos>())
{
	m_inspector = inspector;
	clear();
}

void sinsp_thread_manager::clear()
{
	m_threadtable.clear();
	m_thread_groups.clear();
	m_last_tid = 0;
	m_last_flush_time_ns = 0;
}

/* This is called on the table after the `/proc` scan */
void sinsp_thread_manager::create_thread_dependencies(const std::shared_ptr<sinsp_threadinfo>& tinfo)
{
	/* This should never happen */
	if(tinfo == nullptr)
	{
		throw sinsp_exception("There is a NULL pointer in the thread table, this should never happen");
	}

	/* For invalid threads we do nothing.
	 * They won't have a valid parent or a valid thread group.
	 * We use them just to see which tid calls a syscall.
	 */
	if(tinfo->is_invalid())
	{
		return;
	}

	/* This is a defensive check, it should never happen
	 * a thread that calls this method should never have a thread group info
	 */
	if(tinfo->m_tginfo != nullptr)
	{
		return;
	}

	bool reaper = false;
	/* reaper should be true if we are an init process for the init namespace or for an inner namespace */
	if(tinfo->m_pid == 1 || tinfo->m_vpid == 1)
	{
		reaper = true;
	}

	/* Create the thread group info for the thread. */
	auto tginfo = m_inspector->m_thread_manager->get_thread_group_info(tinfo->m_pid);
	if(tginfo == nullptr)
	{
		tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, reaper, tinfo);
		m_inspector->m_thread_manager->set_thread_group_info(tinfo->m_pid, tginfo);
	}
	else
	{
		tginfo->add_thread_to_group(tinfo, tinfo->is_main_thread());
	}
	tinfo->m_tginfo = tginfo;

	/* init group has no parent */
	if(tinfo->m_pid == 1)
	{
		return;
	}

	/* Assign the child to the parent for the first time, we are a thread
	 * just created and we need to assign us to a parent.
	 * Remember that in `/proc` scan the `ptid` is `ppid`.
	 * If we don't find the parent in the table we can do nothing, so we consider
	 * INIT as the new parent.
	 * Here we avoid scanning `/proc` to not trigger a possible recursion
	 * on all the parents
	 */
	auto parent_thread = m_inspector->get_thread_ref(tinfo->m_ptid, false);
	if(parent_thread == nullptr || parent_thread->is_invalid())
	{
		/* If we have a valid parent we assign the new child to it otherwise we set ptid = 0. */
		tinfo->m_ptid = 0;
		return;
	}
	parent_thread->add_child(tinfo);
}

std::unique_ptr<sinsp_threadinfo> sinsp_thread_manager::new_threadinfo() const
{
	auto tinfo = new sinsp_threadinfo(m_inspector, dynamic_fields());
	return std::unique_ptr<sinsp_threadinfo>(tinfo);
}

std::unique_ptr<sinsp_fdinfo> sinsp_thread_manager::new_fdinfo() const
{
	return sinsp_fdtable(m_inspector).new_fdinfo();
}

/* Can be called when:
 * 1. We crafted a new event to create in clone parsers. (`from_scap_proctable==false`)
 * 2. We are doing a proc scan with a callback or without. (`from_scap_proctable==true`)
 * 3. We are trying to obtain thread info from /proc through `get_thread_ref`
 */
std::shared_ptr<sinsp_threadinfo> sinsp_thread_manager::add_thread(std::unique_ptr<sinsp_threadinfo> threadinfo, bool from_scap_proctable)
{

	/* We have no more space */
	if(m_threadtable.size() >= m_max_thread_table_size
	   && threadinfo->m_pid != m_inspector->m_self_pid
	)
	{
		if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
		{
			// rate limit messages to avoid spamming the logs
			if (m_inspector->get_sinsp_stats_v2()->m_n_drops_full_threadtable % m_max_thread_table_size == 0)
			{
				libsinsp_logger()->format(sinsp_logger::SEV_INFO, "Thread table full, dropping tid %lu (pid %lu, comm \"%s\")",
					threadinfo->m_tid, threadinfo->m_pid, threadinfo->m_comm.c_str());
			}
			m_inspector->get_sinsp_stats_v2()->m_n_drops_full_threadtable++;
		}
		return nullptr;
	}

	auto tinfo_shared_ptr = std::shared_ptr<sinsp_threadinfo>(std::move(threadinfo));

	if(!from_scap_proctable)
	{
		create_thread_dependencies(tinfo_shared_ptr);
	}

	if (tinfo_shared_ptr->dynamic_fields() != dynamic_fields())
	{
		throw sinsp_exception("adding entry with incompatible dynamic defs to thread table");
	}

	if (tinfo_shared_ptr->get_fdtable().dynamic_fields() != m_fdtable_dyn_fields)
	{
		throw sinsp_exception("adding entry with incompatible dynamic defs to of file descriptor sub-table");
	}

	tinfo_shared_ptr->compute_program_hash();
	m_threadtable.put(tinfo_shared_ptr);

	if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
	{
		m_inspector->get_sinsp_stats_v2()->m_n_added_threads++;
	}

	return tinfo_shared_ptr;
}

/* Taken from `find_new_reaper` kernel function:
 *
 * When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists.
 * 2. give them to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give them to the init process (PID 1) in our pid namespace
 */
sinsp_threadinfo* sinsp_thread_manager::find_new_reaper(sinsp_threadinfo* tinfo)
{
	if(tinfo == nullptr)
	{
		throw sinsp_exception("cannot call find_new_reaper() on a null tinfo");
	}

	/* First we check in our thread group for alive threads */
	if(tinfo->m_tginfo != nullptr && tinfo->m_tginfo->get_thread_count() > 0)
	{
		for(const auto& thread_weak : tinfo->m_tginfo->get_thread_list())
		{
			if(thread_weak.expired())
			{
				continue;
			}
			auto thread = thread_weak.lock().get();
			if(!thread->is_dead() && thread != tinfo)
			{
				return thread;
			}
		}
	}

	/* This is a best-effort logic to detect loops.
	 * If a parent points to a thread that is a child of
	 * the current `tinfo` it is possible that we are not
	 * able to detect the loop and we assign the wrong reaper.
	 * By the way, this should never happen and this logic is here
	 * just to avoid infinite loops, is not here to guarantee 100%
	 * correctness.
	 * We should never have a self-loop but if we have it
	 * we break it and we return a `nullptr` as a reaper.
	 */
	std::unordered_set<int64_t> loop_detection_set{tinfo->m_tid};
	uint16_t prev_set_size = 1;

	auto parent_tinfo = tinfo->get_parent_thread();
	while(parent_tinfo != nullptr)
	{
		prev_set_size = loop_detection_set.size();
		loop_detection_set.insert(parent_tinfo->m_tid);
		if(loop_detection_set.size() == prev_set_size)
		{
			/* loop detected */
			ASSERT(false);
			break;
		}

		/* The only possible case in which we break here is:
		 * - the parent is not in a namespace while the child yes
		 *
		 * WARNING: this is a best-effort check, in sinsp we have no knowledge of
		 * namespace level so it's possible that the parent is in a different namespace causing
		 * a container escape! We are not able to detect it with the actual info.
		 */
		if(parent_tinfo->is_in_pid_namespace() != tinfo->is_in_pid_namespace())
		{
			break;
		}

		if(parent_tinfo->m_tginfo != nullptr &&
			parent_tinfo->m_tginfo->is_reaper() &&
			parent_tinfo->m_tginfo->get_thread_count() > 0)
		{
			for(const auto& thread_weak : parent_tinfo->m_tginfo->get_thread_list())
			{
				if(thread_weak.expired())
				{
					continue;
				}
				auto thread = thread_weak.lock().get();
				if(!thread->is_dead())
				{
					return thread;
				}
			}
		}
		parent_tinfo = parent_tinfo->get_parent_thread();
	}

	return nullptr;
}

void sinsp_thread_manager::remove_main_thread_fdtable(sinsp_threadinfo* main_thread)
{
	///todo(@Andreagit97): all this logic is useful only if we have a `m_fd_listener`
	///we could avoid it if not present.

	/* Please note that the main thread is not always here, it is possible
	 * that for some reason we lose it!
	 */
	if(main_thread == nullptr)
	{
		return;
	}

	sinsp_fdtable* fd_table_ptr = main_thread->get_fd_table();
	if(fd_table_ptr == nullptr)
	{
		return;
	}

	erase_fd_params eparams;
	eparams.m_remove_from_table = false;
	eparams.m_tinfo = main_thread;
	eparams.m_ts = m_inspector->get_lastevent_ts();

	fd_table_ptr->loop([&](int64_t fd, sinsp_fdinfo& fdinfo) {
		eparams.m_fd = fd;

		//
		// The canceled fd should always be deleted immediately, so if it appears
		// here it means we have a problem.
		//
		ASSERT(eparams.m_fd != CANCELED_FD_NUMBER);
		eparams.m_fdinfo = &fdinfo;

		/* Here we are just calling the `on_erase` callback */
		m_inspector->get_parser()->erase_fd(&eparams);
		return true;
	});
}

void sinsp_thread_manager::remove_thread(int64_t tid)
{
	auto thread_to_remove = m_threadtable.get_ref(tid);

	/* This should never happen but just to be sure. */
	if(thread_to_remove == nullptr)
	{
		// Extra m_inspector nullptr check
		if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
		{
			m_inspector->get_sinsp_stats_v2()->m_n_failed_thread_lookups++;
		}
		return;
	}

	/* [Remove invalid threads]
	 * All threads should have a m_tginfo apart from the invalid ones
	 * which don't have a group or children.
	 */
	if(thread_to_remove->is_invalid() || thread_to_remove->m_tginfo == nullptr)
	{
		thread_to_remove->remove_child_from_parent();
		m_threadtable.erase(tid);
		m_last_tid = -1;
		return;
	}

	/* [Mark the thread as dead]
	 * If didn't lose the PROC_EXIT event we have already done it
	 */
	if(!thread_to_remove->is_dead())
	{
		/* we should decrement only if the thread is alive */
		thread_to_remove->m_tginfo->decrement_thread_count();
		thread_to_remove->set_dead();
	}

	/* [Reparent children]
	 * There are different cases:
	 * 1. We have no children so we have nothing to reparent.
	 * 2. We receive a PROC_EXIT event for this thread, with reaper info:
	 *   - Reaper 0 means that the kernel didn't find any children for this thread,
	 *     probably we are not correctly aligned with it. In this case, we will use our userspace logic
	 *     to find a reaper.
	 *   - Reaper -1 means that we cannot find the correct reaper info in the kernel due
	 *     to BPF verifier limits. In this case, we will use our userspace logic to find a reaper.
	 *   - Reaper > 0 means the kernel sent us a valid reaper we will use it if present in our thread table.
	 * 	   If not present we will use our userspace logic.
	 * 3. We receive an old version of the PROC_EXIT event without reaper info. In this case,
	 *    we use our userspace logic.
	 * 4. We lost the PROC_EXIT event, so we are here because the purging logic called us. Also
	 *    in this case we use our userspace logic.
	 *
	 * So excluding the case in which the kernel sent us a valid reaper we always fallback to
	 * our userspace logic.
	 */
	if(thread_to_remove->m_children.size())
	{
		sinsp_threadinfo *reaper_tinfo = nullptr;

		if(thread_to_remove->m_reaper_tid > 0)
		{
			/* The kernel sent us a valid reaper
			 * We should have the reaper thread in the table, but if we don't have
			 * it, we try to create it from /proc
			 */
			reaper_tinfo = m_inspector->get_thread_ref(thread_to_remove->m_reaper_tid , true).get();
		}

		if(reaper_tinfo == nullptr || reaper_tinfo->is_invalid())
		{
			/* Fallback case:
		 	 * We search for a reaper in best effort traversing our table
		 	 */
			reaper_tinfo = find_new_reaper(thread_to_remove.get());
		}

		if(reaper_tinfo != nullptr)
		{
			/* We update the reaper tid if necessary. */
			thread_to_remove->m_reaper_tid = reaper_tinfo->m_tid;

			/* If that thread group was not marked as a reaper we mark it now.
			 * Since the reaper could be also a thread in the same thread group
			 * we need to exclude that case. In all other cases, we want to mark
			 * the thread group as a reaper:
			 * - init process of a namespace.
			 * - process that called prctl on itself.
			 * Please note that in the kernel init processes are not marked with `is_child_subreaper`
			 * but here we don't make distinctions we mark reapers and sub reapers with the same flag.
			 */
			if(reaper_tinfo->m_pid != thread_to_remove->m_pid && reaper_tinfo->m_tginfo)
			{
				reaper_tinfo->m_tginfo->set_reaper(true);
			}
		}
		thread_to_remove->assign_children_to_reaper(reaper_tinfo);
	}

	/* [Remove main thread]
	 * We remove the main thread if there are no other threads in the group
	 */
	if((thread_to_remove->m_tginfo->get_thread_count() == 0))
	{
		remove_main_thread_fdtable(thread_to_remove->get_main_thread());

		/* we remove the main thread and the thread group */
		/* even if thread_to_remove is not the main thread the parent will be
		 * the same so it's ok.
		 */
		thread_to_remove->remove_child_from_parent();
		m_thread_groups.erase(thread_to_remove->m_pid);
		m_threadtable.erase(thread_to_remove->m_pid);
	}

	/* [Remove the current thread]
	 * We remove the current thread if it is not the main one.
	 * If we are the main thread and it's time to be removed, we are removed
	 * in the previous `if`.
	 */
	if(!thread_to_remove->is_main_thread())
	{
		thread_to_remove->remove_child_from_parent();
		m_threadtable.erase(tid);
	}

	/* Maybe we removed the thread info that was cached, we clear
	 * the cache just to be sure.
	 */
	m_last_tid = -1;
	if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
	{
		m_inspector->get_sinsp_stats_v2()->m_n_removed_threads++;
	}
}

void sinsp_thread_manager::fix_sockets_coming_from_proc()
{
	m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		tinfo.fix_sockets_coming_from_proc();
		return true;
	});
}

void sinsp_thread_manager::clear_thread_pointers(sinsp_threadinfo& tinfo)
{
	sinsp_fdtable* fdt = tinfo.get_fd_table();
	if(fdt != NULL)
	{
		fdt->reset_cache();
	}
}

void sinsp_thread_manager::reset_child_dependencies()
{
	m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		tinfo.clean_expired_children();
		/* Little optimization: only the main thread cleans the thread group from expired threads.
		 * Downside: if the main thread is not present in the thread group because we lost it we don't
		 * clean the thread group from expired threads.
		 */
		if(tinfo.is_main_thread() && tinfo.m_tginfo != nullptr)
		{
			tinfo.m_tginfo->clean_expired_threads();
		}
		clear_thread_pointers(tinfo);
		return true;
	});
}

void sinsp_thread_manager::create_thread_dependencies_after_proc_scan()
{
	m_threadtable.const_loop_shared_pointer([&](const std::shared_ptr<sinsp_threadinfo>& tinfo) {
		create_thread_dependencies(tinfo);
		return true;
	});
}

void sinsp_thread_manager::free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free)
{
	for(uint32_t j = 0; j < fdinfos_to_free->size(); j++)
	{
		free(fdinfos_to_free->at(j));
	}

	fdinfos_to_free->clear();
}

// NOTE: This does *not* populate any array-based fields (comm, exe,
// exepath, args, env, cwd, cgroups, root)
void sinsp_thread_manager::thread_to_scap(sinsp_threadinfo& tinfo, 	scap_threadinfo* sctinfo)
{
	//
	// Fill in the thread data
	//

	// NOTE: This is doing a shallow copy of the strings from
	// tinfo, and is valid only as long as tinfo is valid.

	sctinfo->tid = tinfo.m_tid;
	sctinfo->pid = tinfo.m_pid;
	sctinfo->ptid = tinfo.m_ptid;
	sctinfo->sid = tinfo.m_sid;
	sctinfo->vpgid = tinfo.m_vpgid;

	sctinfo->flags = tinfo.m_flags ;
	sctinfo->fdlimit = tinfo.m_fdlimit;
	sctinfo->uid = tinfo.m_user.uid();
	sctinfo->gid = tinfo.m_group.gid();
	sctinfo->vmsize_kb = tinfo.m_vmsize_kb;
	sctinfo->vmrss_kb = tinfo.m_vmrss_kb;
	sctinfo->vmswap_kb = tinfo.m_vmswap_kb;
	sctinfo->pfmajor = tinfo.m_pfmajor;
	sctinfo->pfminor = tinfo.m_pfminor;
	sctinfo->vtid = tinfo.m_vtid;
	sctinfo->vpid = tinfo.m_vpid;
	sctinfo->fdlist = NULL;
	sctinfo->loginuid = tinfo.m_loginuser.uid();
	sctinfo->filtered_out = tinfo.m_filtered_out;
}

void sinsp_thread_manager::dump_threads_to_file(scap_dumper_t* dumper)
{
	if(m_threadtable.size() == 0)
	{
		return;
	}

	scap_dumper_t *proclist_dumper = scap_write_proclist_begin();
	if(proclist_dumper == nullptr)
	{
			throw sinsp_exception("Failed to create proclist dumper");
	}

	uint32_t totlen = 0;
	m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		if(tinfo.m_filtered_out)
		{
			return true;
		}

		scap_threadinfo sctinfo {};
		struct iovec *args_iov, *envs_iov, *cgroups_iov;
		int argscnt, envscnt, cgroupscnt;
		std::string argsrem, envsrem, cgroupsrem;
		uint32_t entrylen = 0;
		const auto& cg = tinfo.cgroups();

		memset(&sctinfo, 0, sizeof(scap_threadinfo));

		thread_to_scap(tinfo, &sctinfo);
		tinfo.args_to_iovec(&args_iov, &argscnt, argsrem);
		tinfo.env_to_iovec(&envs_iov, &envscnt, envsrem);
		tinfo.cgroups_to_iovec(&cgroups_iov, &cgroupscnt, cgroupsrem, cg);

		if(scap_write_proclist_entry_bufs(proclist_dumper, &sctinfo, &entrylen,
						  tinfo.m_comm.c_str(),
						  tinfo.m_exe.c_str(),
						  tinfo.m_exepath.c_str(),
						  args_iov, argscnt,
						  envs_iov, envscnt,
						  (tinfo.get_cwd() == "" ? "/" : tinfo.get_cwd().c_str()),
						  cgroups_iov, cgroupscnt,
						  tinfo.m_root.c_str()) != SCAP_SUCCESS)
		{
			sinsp_exception exc(scap_dump_getlasterr(proclist_dumper));
			scap_dump_close(proclist_dumper);
			throw exc;
		}

		totlen += entrylen;

		free(args_iov);
		free(envs_iov);
		free(cgroups_iov);

		return true;
	});

	if(scap_write_proclist_end(dumper, proclist_dumper, totlen) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_dump_getlasterr(dumper));
	}

	//
	// Dump the FDs
	//

	m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		if(tinfo.m_filtered_out)
		{
			return true;
		}

		scap_threadinfo sctinfo {};

		memset(&sctinfo, 0, sizeof(scap_threadinfo));

		// Note: as scap_fd_add/scap_write_proc_fds do not use
		// any of the array-based fields like comm, etc. a
		// shallow copy is safe
		thread_to_scap(tinfo, &sctinfo);

		if(tinfo.is_main_thread())
		{
			//
			// Add the FDs
			//
			sinsp_fdtable* fd_table_ptr = tinfo.get_fd_table();
			if(fd_table_ptr == NULL)
			{
				return false;
			}

			bool should_exit = false;
			fd_table_ptr->loop([&](int64_t fd, sinsp_fdinfo& info) {
				//
				// Allocate the scap fd info
				//
				scap_fdinfo* scfdinfo = (scap_fdinfo*)malloc(sizeof(scap_fdinfo));
				if(scfdinfo == NULL)
				{
					scap_fd_free_proc_fd_table(&sctinfo);
					should_exit = true;
					return false;
				}

				//
				// Populate the fd info
				//
				fd_to_scap(scfdinfo, &info);

				//
				// Add the new fd to the scap table.
				//
				if(scap_fd_add(&sctinfo, scfdinfo) != SCAP_SUCCESS)
				{
					scap_fd_free_proc_fd_table(&sctinfo);
					throw sinsp_exception("Failed to add fd to hash table");
				}

				return true;
			});

			if (should_exit)
			{
				return false;
			}
		}

		//
		// Dump the thread to disk
		//
		if(scap_write_proc_fds(dumper, &sctinfo) != SCAP_SUCCESS)
		{
			throw sinsp_exception("error calling scap_write_proc_fds in sinsp_thread_manager::dump_threads_to_file (" + std::string(scap_dump_getlasterr(dumper)) + ")");
		}

		scap_fd_free_proc_fd_table(&sctinfo);
		return true;
	});
}

threadinfo_map_t::ptr_t sinsp_thread_manager::get_thread_ref(int64_t tid, bool query_os_if_not_found, bool lookup_only, bool main_thread)
{
    auto sinsp_proc = find_thread(tid, lookup_only);

    if(!sinsp_proc && query_os_if_not_found &&
       (m_threadtable.size() < m_max_thread_table_size || tid == m_inspector->m_self_pid))
    {
        // Certain code paths can lead to this point from scap_open() (incomplete example:
        // scap_proc_scan_proc_dir() -> resolve_container() -> get_env()). Adding a
        // defensive check here to protect both, callers of get_env and get_thread.
        if (!m_inspector->get_scap_handle())
        {
            libsinsp_logger()->format(sinsp_logger::SEV_INFO, "%s: Unable to complete for tid=%"
                            PRIu64 ": sinsp::scap_t* is uninitialized", __func__, tid);
            return NULL;
        }

        scap_threadinfo scap_proc {};
        bool have_scap_proc = false;

        // leaving scap_proc uninitialized could lead to undefined behaviour.
        // to be safe we should initialized to zero.
        memset(&scap_proc, 0, sizeof(scap_threadinfo));

        scap_proc.tid = -1;
        scap_proc.pid = -1;
        scap_proc.ptid = -1;

		// unfortunately, sinsp owns the threade factory
        auto newti = m_inspector->build_threadinfo();

        m_n_proc_lookups++;

        if(main_thread)
        {
            m_n_main_thread_lookups++;
        }

        if(m_n_proc_lookups == m_max_n_proc_lookups)
        {
            libsinsp_logger()->format(sinsp_logger::SEV_INFO, "Reached max process lookup number, duration=%" PRIu64 "ms",
                m_n_proc_lookups_duration_ns / 1000000);
        }

        if(m_max_n_proc_lookups < 0 ||
           m_n_proc_lookups <= m_max_n_proc_lookups)
        {
            bool scan_sockets = false;

            if(m_max_n_proc_socket_lookups < 0 ||
               m_n_proc_lookups <= m_max_n_proc_socket_lookups)
            {
                scan_sockets = true;
                if(m_n_proc_lookups == m_max_n_proc_socket_lookups)
                {
                    libsinsp_logger()->format(sinsp_logger::SEV_INFO, "Reached max socket lookup number, tid=%" PRIu64 ", duration=%" PRIu64 "ms",
                        tid, m_n_proc_lookups_duration_ns / 1000000);
                }
            }

            uint64_t ts = sinsp_utils::get_current_time_ns();
            if(scap_proc_get(m_inspector->get_scap_platform(), tid, &scap_proc, scan_sockets) == SCAP_SUCCESS)
            {
                have_scap_proc = true;
            }
            m_n_proc_lookups_duration_ns += sinsp_utils::get_current_time_ns() - ts;
        }

        if(have_scap_proc)
        {
            newti->init(&scap_proc);
        }
        else
        {
            //
            // Add a fake entry to avoid a continuous lookup
            //
            newti->m_tid = tid;
            newti->m_pid = -1;
            newti->m_ptid = -1;
            newti->m_reaper_tid = -1;
            newti->m_not_expired_children = 0;
            newti->m_comm = "<NA>";
            newti->m_exe = "<NA>";
            newti->m_user.set_uid(0xffffffff);
            newti->m_group.set_gid(0xffffffff);
            newti->m_loginuser.set_uid(0xffffffff);
        }

        //
        // Done. Add the new thread to the list.
        //
        add_thread(std::move(newti), false);
        sinsp_proc = find_thread(tid, lookup_only);
    }

    return sinsp_proc;
}

/* `lookup_only==true` means that we don't fill the `m_last_tinfo` field */
threadinfo_map_t::ptr_t sinsp_thread_manager::find_thread(int64_t tid, bool lookup_only)
{
	threadinfo_map_t::ptr_t thr;
	//
	// Try looking up in our simple cache
	//
	if(tid == m_last_tid)
	{
		thr = m_last_tinfo.lock();
		if (thr)
		{
			if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
			{
				m_inspector->get_sinsp_stats_v2()->m_n_cached_thread_lookups++;
			}
			// This allows us to avoid performing an actual timestamp lookup
			// for something that may not need to be precise
			thr->m_lastaccess_ts = m_inspector->get_lastevent_ts();
			return thr;
		}
	}

	//
	// Caching failed, do a real lookup
	//
	thr = m_threadtable.get_ref(tid);

	if(thr)
	{
		if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
		{
			m_inspector->get_sinsp_stats_v2()->m_n_noncached_thread_lookups++;
		}
		if(!lookup_only)
		{
			m_last_tinfo.reset();
			m_last_tid = tid;
			m_last_tinfo = thr;
			thr->m_lastaccess_ts = m_inspector->get_lastevent_ts();
		}
		return thr;
	}
	else
	{
		if (m_inspector != nullptr && m_inspector->get_sinsp_stats_v2())
		{
			m_inspector->get_sinsp_stats_v2()->m_n_failed_thread_lookups++;
		}
		return NULL;
	}
}

void sinsp_thread_manager::set_max_thread_table_size(uint32_t value)
{
    m_max_thread_table_size = value;
}

std::unique_ptr<libsinsp::state::table_entry> sinsp_thread_manager::new_entry() const
{
	return m_inspector->build_threadinfo();
}

void sinsp_thread_manager::set_tinfo_shared_dynamic_fields(sinsp_threadinfo& tinfo) const
{
	if (tinfo.dynamic_fields() == nullptr)
	{
		tinfo.set_dynamic_fields(dynamic_fields());
	}
	tinfo.get_fdtable().set_dynamic_fields(m_fdtable_dyn_fields);
}

void sinsp_thread_manager::set_fdinfo_shared_dynamic_fields(sinsp_fdinfo& fdinfo) const
{
	if (fdinfo.dynamic_fields() == nullptr)
	{
		fdinfo.set_dynamic_fields(m_fdtable_dyn_fields);
	}
}
