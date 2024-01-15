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
#include "sinsp.h"
#include "sinsp_int.h"
#include "scap-int.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdinfo implementation
///////////////////////////////////////////////////////////////////////////////
template<> sinsp_fdinfo_t::sinsp_fdinfo()
{
	m_type = SCAP_FD_UNINITIALIZED;
	m_flags = FLAGS_NONE;
	m_usrstate = NULL;
	m_name = "";
	m_name_raw = "";
	m_oldname = "";
	m_dev = 0;
	m_mount_id = 0;
	m_ino = 0;
	m_openflags = 0;
	m_pid = 0;
}

template<> void sinsp_fdinfo_t::reset()
{
	m_type = SCAP_FD_UNINITIALIZED;
	m_flags = FLAGS_NONE;
	m_usrstate = NULL;
	m_name = "";
	m_name_raw = "";
	m_oldname = "";
	m_dev = 0;
	m_mount_id = 0;
	m_ino = 0;
	m_openflags = 0;
	m_pid = 0;
}

template<> std::string* sinsp_fdinfo_t::tostring()
{
	return &m_name;
}

template<> char sinsp_fdinfo_t::get_typechar()
{
	switch(m_type)
	{
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

template<> char* sinsp_fdinfo_t::get_typestring() const
{
	switch(m_type)
	{
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
		return (char*)"file";
	case SCAP_FD_DIRECTORY:
		return (char*)"directory";
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
		return (char*)"ipv4";
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		return (char*)"ipv6";
	case SCAP_FD_UNIX_SOCK:
		return (char*)"unix";
	case SCAP_FD_FIFO:
		return (char*)"pipe";
	case SCAP_FD_EVENT:
		return (char*)"event";
	case SCAP_FD_SIGNALFD:
		return (char*)"signalfd";
	case SCAP_FD_EVENTPOLL:
		return (char*)"eventpoll";
	case SCAP_FD_INOTIFY:
		return (char*)"inotify";
	case SCAP_FD_TIMERFD:
		return (char*)"timerfd";
	case SCAP_FD_NETLINK:
		return (char*)"netlink";
	case SCAP_FD_BPF:
		return (char*)"bpf";
	case SCAP_FD_USERFAULTFD:
		return (char*)"userfaultfd";
	case SCAP_FD_IOURING:
		return (char*)"io_uring";
	case SCAP_FD_MEMFD:
		return (char*)"memfd";	
	case SCAP_FD_PIDFD:
		return (char*)"pidfd";
	default:
		return (char*)"<NA>";
	}
}

template<> std::string sinsp_fdinfo_t::tostring_clean()
{
	std::string m_tstr = m_name;
	sanitize_string(m_tstr);

	return m_tstr;
}

template<> void sinsp_fdinfo_t::add_filename_raw(std::string_view rawpath)
{
	m_name_raw = std::string(rawpath);
}

template<> void sinsp_fdinfo_t::add_filename(std::string_view fullpath)
{
	m_name = std::string(fullpath);
}

template<> bool sinsp_fdinfo_t::set_net_role_by_guessing(sinsp* inspector,
										  sinsp_threadinfo* ptinfo,
										  sinsp_fdinfo_t* pfdinfo,
										  bool incoming)
{
	//
	// If this process owns the port, mark it as server, otherwise mark it as client
	//
	if(ptinfo->is_bound_to_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport))
	{
		if(ptinfo->uses_client_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport))
		{
			goto wildass_guess;
		}

		pfdinfo->set_role_server();
		return true;
	}
	else
	{
		pfdinfo->set_role_client();
		return true;
	}

wildass_guess:
	if(!(pfdinfo->m_flags & (sinsp_fdinfo_t::FLAGS_ROLE_CLIENT | sinsp_fdinfo_t::FLAGS_ROLE_SERVER)))
	{
		//
		// We just assume that a server usually starts with a read and a client with a write
		//
		if(incoming)
		{
			pfdinfo->set_role_server();
		}
		else
		{
			pfdinfo->set_role_client();
		}
	}

	return true;
}

template<> scap_l4_proto sinsp_fdinfo_t::get_l4proto()
{
	scap_fd_type evt_type = m_type;

	if(evt_type == SCAP_FD_IPV4_SOCK)
	{
		if((scap_l4_proto)m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			return SCAP_L4_RAW;
		}

		if(is_role_none())
		{
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv4info.m_fields.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
	{
		return (scap_l4_proto)(m_sockinfo.m_ipv4serverinfo.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV6_SOCK)
	{
		if((scap_l4_proto)m_sockinfo.m_ipv6info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			return SCAP_L4_RAW;
		}

		if(is_role_none())
		{
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv6info.m_fields.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
	{
		return (scap_l4_proto)(m_sockinfo.m_ipv6serverinfo.m_l4proto);
	}
	else
	{
		return SCAP_L4_NA;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdtable implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_fdtable::sinsp_fdtable(sinsp* inspector)
{
	m_inspector = inspector;
	reset_cache();
}

sinsp_fdinfo_t* sinsp_fdtable::find(int64_t fd)
{
	std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;

		//
		// Try looking up in our simple cache
		//
		if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd)
		{
			if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
			{
				m_inspector->m_sinsp_stats_v2->m_n_cached_fd_lookups++;
			}
			return m_last_accessed_fdinfo;
		}

		//
		// Caching failed, do a real lookup
		//
		fdit = m_table.find(fd);

		if(fdit == m_table.end())
		{
			if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
			{
				m_inspector->m_sinsp_stats_v2->m_n_failed_fd_lookups++;
			}
			return NULL;
		}
		else
		{
			if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
			{
				m_inspector->m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
			}

			m_last_accessed_fd = fd;
			m_last_accessed_fdinfo = &(fdit->second);
			lookup_device(&(fdit->second), fd);
			return &(fdit->second);
		}
}

sinsp_fdinfo_t* sinsp_fdtable::add(int64_t fd, sinsp_fdinfo_t* fdinfo)
{
	//
	// Look for the FD in the table
	//
	auto it = m_table.find(fd);

	// Three possible exits here:
	// 1. fd is not on the table
	//   a. the table size is under the limit so create a new entry
	//   b. table size is over the limit, discard the fd
	// 2. fd is already in the table, replace it
	if(it == m_table.end())
	{
		if(m_table.size() < m_inspector->m_max_fdtable_size)
		{
			//
			// No entry in the table, this is the normal case
			//
			m_last_accessed_fd = -1;
			if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
			{
				m_inspector->m_sinsp_stats_v2->m_n_added_fds++;
			}

			std::pair<std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator, bool> insert_res = m_table.emplace(fd, *fdinfo);
			return &(insert_res.first->second);
		}
		else
		{
			return nullptr;
		}
	}
	else
	{
		//
		// the fd is already in the table.
		//
		if(it->second.m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS)
		{
			//
			// Sometimes an FD-creating syscall can be called on an FD that is being closed (i.e
			// the close enter has arrived but the close exit has not arrived yet).
			// If this is the case, mark the new entry so that the successive close exit won't
			// destroy it.
			//
			fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
			fdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;

			m_table[CANCELED_FD_NUMBER] = it->second;
		}
		else
		{
			//
			// This can happen if:
			//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
			// choice. We include an assertion to catch the situation.
			//
			// XXX Can't have this enabled until the FD_CLOEXEC flag is supported
			//ASSERT(false);
		}

		//
		// Replace the fd as a struct copy
		//
		it->second.copy(*fdinfo, true);
		return &(it->second);
	}
}

void sinsp_fdtable::erase(int64_t fd)
{
	std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit = m_table.find(fd);

	if(fd == m_last_accessed_fd)
	{
		m_last_accessed_fd = -1;
	}

	if(fdit == m_table.end())
	{
		//
		// Looks like there's no fd to remove.
		// Either the fd creation event was dropped or (more likely) our logic doesn't support the
		// call that created this fd. The assertion will detect it, while in release mode we just
		// keep going.
		//
		ASSERT(false);
		if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
		{
			m_inspector->m_sinsp_stats_v2->m_n_failed_fd_lookups++;
		}
	}
	else
	{
		m_table.erase(fdit);
		if (m_inspector != nullptr && m_inspector->m_sinsp_stats_v2)
		{
			m_inspector->m_sinsp_stats_v2->m_n_noncached_fd_lookups++;
			m_inspector->m_sinsp_stats_v2->m_n_removed_fds++;
		}
	}
}

void sinsp_fdtable::clear()
{
	m_table.clear();
}

size_t sinsp_fdtable::size()
{
	return m_table.size();
}

void sinsp_fdtable::reset_cache()
{
	m_last_accessed_fd = -1;
}

void sinsp_fdtable::lookup_device(sinsp_fdinfo_t* fdi, uint64_t fd)
{
#ifdef HAS_CAPTURE
#ifndef _WIN32
	if(m_inspector == nullptr || m_inspector->is_offline() ||
	   (m_inspector->is_plugin() && !m_inspector->is_syscall_plugin()))
	{
		return;
	}

	if(fdi->is_file() && fdi->m_dev == 0 && fdi->m_mount_id != 0)
	{
		char procdir[SCAP_MAX_PATH_SIZE];
		snprintf(procdir, sizeof(procdir), "%s/proc/%ld/", scap_get_host_root(), m_tid);
		fdi->m_dev = scap_get_device_by_mount_id(m_inspector->get_scap_platform(), procdir, fdi->m_mount_id);
		fdi->m_mount_id = 0; // don't try again
	}
#endif // _WIN32
#endif // HAS_CAPTURE
}
