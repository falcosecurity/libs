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

#include <libsinsp/sinsp_filtercheck_fd.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/dns_manager.h>

using namespace std;

#define RETURN_EXTRACT_VAR(x) do {  \
        *len = sizeof((x));         \
        return (uint8_t*) &(x);     \
} while(0)

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

#define RETURN_EXTRACT_CSTR(x) do {             \
        if((x))                                 \
        {                                       \
                *len = strlen((char *) ((x)));  \
        }                                       \
        return (uint8_t*) ((x));                \
} while(0)

static inline bool str_match_start(const std::string& val, size_t len, const char* m)
{
	return val.compare(0, len, m) == 0;
}

#define STR_MATCH(s) str_match_start(val, sizeof (s) -1, s)

static const filtercheck_field_info sinsp_filter_check_fd_fields[] =
{
	{PT_INT64, EPF_NONE, PF_ID, "fd.num", "FD Number", "the unique number identifying the file descriptor."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.type", "FD Type", "type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify'  'signalfd' or 'memfd'."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.typechar", "FD Type Char", "type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'b' for bpf, 'u' for userfaultd, 'r' for io_uring, 'm' for memfd ,'o' for unknown."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.name", "FD Name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.directory", "FD Directory", "If the fd is a file, the directory that contains it."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.filename", "FD Filename", "If the fd is a file, the filename without the path."},
	{PT_IPADDR, EPF_FILTER_ONLY, PF_NA, "fd.ip", "FD IP Address", "matches the ip address (client or server) of the fd."},
	{PT_IPADDR, EPF_NONE, PF_NA, "fd.cip", "FD Client Address", "client IP address."},
	{PT_IPADDR, EPF_NONE, PF_NA, "fd.sip", "FD Server Address", "server IP address."},
	{PT_IPADDR, EPF_NONE, PF_NA, "fd.lip", "FD Local Address", "local IP address."},
	{PT_IPADDR, EPF_NONE, PF_NA, "fd.rip", "FD Remote Address", "remote IP address."},
	{PT_PORT, EPF_FILTER_ONLY, PF_DEC, "fd.port", "FD Port", "matches the port (either client or server) of the fd."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.cport", "FD Client Port", "for TCP/UDP FDs, the client port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.sport", "FD Server Port", "for TCP/UDP FDs, server port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.lport", "FD Local Port", "for TCP/UDP FDs, the local port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.rport", "FD Remote Port", "for TCP/UDP FDs, the remote port."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.l4proto", "FD IP Protocol", "the IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.sockfamily", "FD Socket Family", "the socket family for socket events. Can be 'ip' or 'unix'."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.is_server", "FD Server", "'true' if the process owning this FD is the server endpoint in the connection."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.uid", "FD ID", "a unique identifier for the FD, created by chaining the FD number and the thread ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.containername", "FD Container Name", "chaining of the container ID and the FD name. Useful when trying to identify which container an FD belongs to."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.containerdirectory", "FD Container Directory", "chaining of the container ID and the directory name. Useful when trying to identify which container a directory belongs to."},
	{PT_PORT, EPF_FILTER_ONLY, PF_NA, "fd.proto", "FD Protocol", "matches the protocol (either client or server) of the fd."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.cproto", "FD Client Protocol", "for TCP/UDP FDs, the client protocol."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.sproto", "FD Server Protocol", "for TCP/UDP FDs, server protocol."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.lproto", "FD Local Protocol", "for TCP/UDP FDs, the local protocol."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.rproto", "FD Remote Protocol", "for TCP/UDP FDs, the remote protocol."},
	{PT_IPNET, EPF_FILTER_ONLY, PF_NA, "fd.net", "FD IP Network", "matches the IP network (client or server) of the fd."},
	{PT_IPNET, EPF_FILTER_ONLY, PF_NA, "fd.cnet", "FD Client Network", "matches the client IP network of the fd."},
	{PT_IPNET, EPF_FILTER_ONLY, PF_NA, "fd.snet", "FD Server Network", "matches the server IP network of the fd."},
	{PT_IPNET, EPF_FILTER_ONLY, PF_NA, "fd.lnet", "FD Local Network", "matches the local IP network of the fd."},
	{PT_IPNET, EPF_FILTER_ONLY, PF_NA, "fd.rnet", "FD Remote Network", "matches the remote IP network of the fd."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.connected", "FD Connected", "for TCP/UDP FDs, 'true' if the socket is connected."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.name_changed", "FD Name Changed", "True when an event changes the name of an fd used by this event. This can occur in some cases such as udp connections where the connection tuple changes."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.cip.name", "FD Client Domain Name", "Domain name associated with the client IP address."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.sip.name", "FD Server Domain Name", "Domain name associated with the server IP address."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.lip.name", "FD Local Domain Name", "Domain name associated with the local IP address."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.rip.name", "FD Remote Domain Name", "Domain name associated with the remote IP address."},
	{PT_INT32, EPF_NONE, PF_HEX, "fd.dev", "FD Device", "device number (major/minor) containing the referenced file"},
	{PT_INT32, EPF_NONE, PF_DEC, "fd.dev.major", "FD Major Device", "major device number containing the referenced file"},
	{PT_INT32, EPF_NONE, PF_DEC, "fd.dev.minor", "FD Minor Device", "minor device number containing the referenced file"},
	{PT_INT64, EPF_NONE, PF_DEC, "fd.ino", "FD Inode Number", "inode number of the referenced file"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.nameraw", "FD Name Raw", "FD full name raw. Just like fd.name, but only used if fd is a file path. File path is kept raw with limited sanitization and without deriving the absolute path."},
	{PT_CHARBUF, EPF_IS_LIST|EPF_ARG_ALLOWED, PF_DEC, "fd.types", "FD Type", "List of FD types in used. Can be passed an fd number e.g. fd.types[0] to get the type of stdout as a single item list."},
};

sinsp_filter_check_fd::sinsp_filter_check_fd()
{
	m_tinfo = NULL;
	m_fdinfo = NULL;
	m_argid = -1;

	m_info.m_name = "fd";
	m_info.m_desc = "Every syscall that has a file descriptor in its arguments has these fields set with information related to the file.";
	m_info.m_fields = sinsp_filter_check_fd_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_fd_fields) / sizeof(sinsp_filter_check_fd_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check* sinsp_filter_check_fd::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_fd();
}

int32_t sinsp_filter_check_fd::extract_arg(string fldname, string val)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);

		m_argid = sinsp_numparser::parsed64(numstr);

		parsed_len++;
	}

	return parsed_len;
}

int32_t sinsp_filter_check_fd::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);

	if(STR_MATCH("fd.types"))
	{
		m_field_id = TYPE_FDTYPES;
		m_field = &m_info.m_fields[m_field_id];
		int32_t res = 0;

		res = extract_arg("fd.types", val);

		if(res == 0)
		{
			m_argid = -1;
			res = (int32_t)val.size();
		}

		return res;
	}

	return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
}

bool sinsp_filter_check_fd::extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings, bool fd_nameraw)
{
	const char* resolved_argstr;
	uint16_t etype = evt->get_type();

	if(PPME_IS_ENTER(etype))
	{
		return false;
	}

	switch(etype)
	{
	case PPME_SYSCALL_OPEN_X:
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT4_5_X:
	case PPME_SOCKET_ACCEPT4_6_X:
	case PPME_SYSCALL_CREAT_X:
		{
			const char* argstr = evt->get_param_as_str(1, &resolved_argstr,
				m_inspector->get_buffer_format());

			if(resolved_argstr[0] != 0)
			{
				m_tstr = resolved_argstr;
			}
			else
			{
				m_tstr = argstr;
			}

			return true;
		}
	case PPME_SOCKET_CONNECT_X:
		{
			const char* argstr = evt->get_param_as_str(1, &resolved_argstr,
				m_inspector->get_buffer_format());

			if(resolved_argstr[0] != 0)
			{
				m_tstr = resolved_argstr;
			}
			else
			{
				m_tstr = argstr;
			}

			return true;
		}
	case PPME_SYSCALL_OPENAT_X:
	case PPME_SYSCALL_OPENAT_2_X:
	case PPME_SYSCALL_OPENAT2_X:
		{
			sinsp_evt enter_evt;
			const sinsp_evt_param *parinfo;

			if(etype == PPME_SYSCALL_OPENAT_X)
			{
				//
				// XXX This is highly inefficient, as it re-requests the enter event and then
				// does unnecessary allocations and copies. We assume that failed openat() happen
				// rarely enough that we don't care.
				//
				if(!m_inspector->get_parser()->retrieve_enter_event(&enter_evt, evt))
				{
					return false;
				}
			}

			parinfo = etype == PPME_SYSCALL_OPENAT_X ? enter_evt.get_param(1) : evt->get_param(2);
			std::string_view name = parinfo->as<std::string_view>();

			parinfo = etype == PPME_SYSCALL_OPENAT_X ? enter_evt.get_param(0) : evt->get_param(1);
			int64_t dirfd = parinfo->as<int64_t>();

			std::string sdir = m_inspector->get_parser()->parse_dirfd(evt, name, dirfd);

			if(fd_nameraw)
			{
				m_tstr = name;
			}
			else
			{
				// fullpath
				m_tstr = sinsp_utils::concatenate_paths(sdir, name); // here we'd like a string
			}

			if(sanitize_strings)
			{
				sanitize_string(m_tstr);
			}

			return true;
		}
	case PPME_SYSCALL_OPEN_BY_HANDLE_AT_X:
		{
			m_tstr = evt->get_param(3)->as<std::string_view>();

			if(sanitize_strings)
			{
				sanitize_string(m_tstr);
			}

			return true;
		}
	default:
		m_tstr = "";
		return true;
	}
}

uint8_t* sinsp_filter_check_fd::extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	//
	// Even is there's no fd, we still try to extract a name from exit events that create
	// one. With these events, the fact that there's no FD means that the call failed,
	// but even if that happened we still want to collect the name.
	//
	switch(m_field_id)
	{
	case TYPE_FDNAME:
	{
		if(extract_fdname_from_creator(evt, len, sanitize_strings) == true)
		{
			RETURN_EXTRACT_STRING(m_tstr);
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_CONTAINERNAME:
	{
		if(extract_fdname_from_creator(evt, len, sanitize_strings) == true)
		{
			m_tstr = m_tinfo->m_container_id + ':' + m_tstr;
			RETURN_EXTRACT_STRING(m_tstr);
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_DIRECTORY:
	case TYPE_CONTAINERDIRECTORY:
	{
		if(extract_fdname_from_creator(evt, len, sanitize_strings) == true)
		{
			if(sanitize_strings)
			{
				sanitize_string(m_tstr);
			}

			size_t pos = m_tstr.rfind('/');
			if(pos != string::npos && pos != 0)
			{
				if(pos < m_tstr.size() - 1)
				{
					m_tstr.resize(pos);
				}
			}
			else
			{
				m_tstr = "/";
			}

			if(m_field_id == TYPE_CONTAINERDIRECTORY)
			{
				m_tstr = m_tinfo->m_container_id + ':' + m_tstr;
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_FILENAME:
	{
		return NULL;
	}
	case TYPE_FDTYPECHAR:
		*len = 1;
		switch(PPME_MAKE_ENTER(evt->get_type()))
		{
		case PPME_SYSCALL_OPEN_E:
		case PPME_SYSCALL_OPENAT_E:
		case PPME_SYSCALL_OPENAT_2_E:
		case PPME_SYSCALL_OPENAT2_E:
		case PPME_SYSCALL_CREAT_E:
			m_tcstr[0] = CHAR_FD_FILE;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SOCKET_SOCKET_E:
		case PPME_SOCKET_ACCEPT_E:
		case PPME_SOCKET_ACCEPT_5_E:
		case PPME_SOCKET_ACCEPT4_E:
		case PPME_SOCKET_ACCEPT4_5_E:
		case PPME_SOCKET_ACCEPT4_6_E:
                	//
                	// Note, this is not accurate, because it always
                	// returns IPv4 even if this could be IPv6 or unix.
                	// For the moment, I assume it's better than nothing, and doing
                	// real event parsing here would be a pain.
                	//
                	m_tcstr[0] = CHAR_FD_IPV4_SOCK;
                	m_tcstr[1] = 0;
                	return m_tcstr;
		case PPME_SYSCALL_PIPE_E:
		case PPME_SYSCALL_PIPE2_E:
			m_tcstr[0] = CHAR_FD_FIFO;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_EVENTFD_E:
		case PPME_SYSCALL_EVENTFD2_E:
			m_tcstr[0] = CHAR_FD_EVENT;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_SIGNALFD_E:
		case PPME_SYSCALL_SIGNALFD4_E:
			m_tcstr[0] = CHAR_FD_SIGNAL;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_TIMERFD_CREATE_E:
			m_tcstr[0] = CHAR_FD_TIMERFD;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_INOTIFY_INIT_E:
		case PPME_SYSCALL_INOTIFY_INIT1_E:
			m_tcstr[0] = CHAR_FD_INOTIFY;
			m_tcstr[1] = 0;
			return m_tcstr;
		default:
			m_tcstr[0] = 'o';
			m_tcstr[1] = 0;
			return m_tcstr;
		}
	case TYPE_FDNAMERAW:
		{
			if(extract_fdname_from_creator(evt, len, sanitize_strings, true) == true)
			{
				remove_duplicate_path_separators(m_tstr);
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	default:
		return NULL;
	}
}

bool sinsp_filter_check_fd::extract(sinsp_evt *evt, OUT std::vector<extract_value_t>& values, bool sanitize_strings)
{
	values.clear();

	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_field_id == TYPE_FDTYPES && m_argid == -1)
	{
		// We are of the form fd.types so gather all open file
		// descriptor types into a (de-duplicated) list
		//
		// Note that fd.types[num] handling is in the following
		// implementation of sinsp_filter_check_fd::extract

		// All of the pointers come from the fd_typesting() function so
		// we shouldn't have the situation of two distinct pointers to
		// the same string literal and we can just compare based on pointer
		std::unordered_set<const char*> fd_types;

		// Iterate over the list of open file descriptors and add all
		// unique file descriptor types to the vector for comparison
		auto fd_type_gather = [&fd_types, &values](uint64_t, const sinsp_fdinfo_t& fdinfo)
		{
			const char* type = fdinfo.get_typestring();

			if (fd_types.emplace(type).second)
			{
				extract_value_t val;
				val.ptr = (uint8_t*)type;
				val.len = strlen(type);

				values.push_back(val);
			}

			return true;
		};

		m_tinfo->loop_fds(fd_type_gather);

		return true;
	}

	return sinsp_filter_check::extract(evt, values, sanitize_strings);
}

uint8_t* sinsp_filter_check_fd::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	ASSERT(evt);

	if(!extract_fd(evt))
	{
		return NULL;
	}

	//
	// TYPE_FDNUM doesn't need fdinfo
	//
	if(m_field_id == TYPE_FDNUM)
	{
		RETURN_EXTRACT_VAR(m_tinfo->m_lastevent_fd);
	}

	switch(m_field_id)
	{
	case TYPE_FDNAME:
	case TYPE_CONTAINERNAME:
		if(m_fdinfo == NULL)
		{
			return extract_from_null_fd(evt, len, sanitize_strings);
		}

		if(evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			int64_t retval = evt->get_param(0)->as<int64_t>();

			if(retval < 0)
			{
				return extract_from_null_fd(evt, len, sanitize_strings);
			}
		}

		if(m_field_id == TYPE_CONTAINERNAME)
		{
			ASSERT(m_tinfo != NULL);
			m_tstr = m_tinfo->m_container_id + ':' + m_fdinfo->m_name;
		}
		else
		{
			m_tstr = m_fdinfo->m_name;
		}

		if(sanitize_strings)
		{
			sanitize_string(m_tstr);
		}
		RETURN_EXTRACT_STRING(m_tstr);
		break;
	case TYPE_FDTYPES:
	case TYPE_FDTYPE:
		if(m_fdinfo == NULL)
		{
			return NULL;
		}
		else
		{
			uint8_t *typestr = (uint8_t*)m_fdinfo->get_typestring();
			RETURN_EXTRACT_CSTR(typestr);
		}
		break;
	case TYPE_DIRECTORY:
	case TYPE_CONTAINERDIRECTORY:
		{
			if(m_fdinfo == NULL)
			{
				return extract_from_null_fd(evt, len, sanitize_strings);
			}

			if(!(m_fdinfo->is_file() || m_fdinfo->is_directory()))
			{
				return NULL;
			}

			m_tstr = m_fdinfo->m_name;
			if(sanitize_strings)
			{
				sanitize_string(m_tstr);
			}

			if(m_fdinfo->is_file())
			{
				size_t pos = m_tstr.rfind('/');
				if(pos != string::npos && pos != 0)
				{
					if(pos < m_tstr.size() - 1)
					{
						m_tstr.resize(pos);
					}
				}
				else
				{
					m_tstr = "/";
				}
			}

			if(m_field_id == TYPE_CONTAINERDIRECTORY)
			{
				m_tstr = m_tinfo->m_container_id + ':' + m_tstr;
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_FILENAME:
		{
			if(m_fdinfo == NULL)
			{
				return extract_from_null_fd(evt, len, sanitize_strings);
			}

			if(!m_fdinfo->is_file())
			{
				return NULL;
			}

			m_tstr = m_fdinfo->m_name;
			if(sanitize_strings)
			{
				sanitize_string(m_tstr);
			}

			size_t pos = m_tstr.rfind('/');
			if(pos != string::npos)
			{
				if(pos < m_tstr.size() - 1)
				{
					m_tstr = m_tstr.substr(pos + 1, string::npos);
				}
			}
			else
			{
				m_tstr = "/";
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_FDTYPECHAR:
		if(m_fdinfo == NULL)
		{
			return extract_from_null_fd(evt, len, sanitize_strings);
		}

		*len = 1;
		m_tcstr[0] = m_fdinfo->get_typechar();
		m_tcstr[1] = 0;
		return m_tcstr;
	case TYPE_CNET:
	case TYPE_CLIENTIP:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
			}
			else if (evt_type == SCAP_FD_IPV6_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip);
			}
		}
		break;
	case TYPE_CLIENTIP_NAME:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			m_tstr.clear();
			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, evt->get_ts());
			}
			else if (evt_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0], evt->get_ts());
			}

			if(!m_tstr.empty())
			{
				RETURN_EXTRACT_STRING(m_tstr);
			}
		}
		break;
	case TYPE_SNET:
	case TYPE_SERVERIP:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip);
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip);
			}
		}
		break;
	case TYPE_SERVERIP_NAME:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			m_tstr.clear();
			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, evt->get_ts());
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip, evt->get_ts());
			}
			else if (evt_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0], evt->get_ts());
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip.m_b[0], evt->get_ts());
			}

			if(!m_tstr.empty())
			{
				RETURN_EXTRACT_STRING(m_tstr);
			}
		}
		break;
	case TYPE_LNET:
	case TYPE_RNET:
	case TYPE_LIP:
	case TYPE_RIP:
	case TYPE_LIP_NAME:
	case TYPE_RIP_NAME:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type != SCAP_FD_IPV4_SOCK &&
			   evt_type != SCAP_FD_IPV6_SOCK)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			/* With local we mean that the client address corresponds to one of our local interfaces */
			bool is_local;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, m_tinfo);
			}
			else
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv6addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip, m_tinfo);
			}

			if(m_field_id != TYPE_LIP_NAME && m_field_id != TYPE_RIP_NAME)
			{
				if(is_local)
				{
					if(m_field_id == TYPE_LIP || m_field_id == TYPE_LNET)
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
						}
						else
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip);
						}
					}
					else
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
						}
						else
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip);
						}
					}
				}
				else
				{
					if(m_field_id == TYPE_LIP || m_field_id == TYPE_LNET)
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
						}
						else
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip);
						}
					}
					else
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
						}
						else
						{
							RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip);
						}
					}
				}
			}
			else
			{
				m_tstr.clear();
				if(is_local)
				{
					if(m_field_id == TYPE_LIP_NAME)
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, evt->get_ts());
						}
						else
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0], evt->get_ts());
						}
					}
					else
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, evt->get_ts());
						}
						else
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0], evt->get_ts());
						}
					}
				}
				else
				{
					if(m_field_id == TYPE_LIP_NAME)
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, evt->get_ts());
						}
						else
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0], evt->get_ts());
						}
					}
					else
					{
						if(evt_type == SCAP_FD_IPV4_SOCK)
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, evt->get_ts());
						}
						else
						{
							m_tstr = sinsp_dns_manager::get().name_of(AF_INET6, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0], evt->get_ts());
						}
					}
				}

				if(!m_tstr.empty())
				{
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}
		}

		break;
	case TYPE_CLIENTPORT:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport);
			}
		}
		break;
	case TYPE_CLIENTPROTO:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			m_tstr = "";
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				m_tstr = port_to_string(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport, this->m_fdinfo->get_l4proto(), m_inspector->m_hostname_and_port_resolution_enabled);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = port_to_string(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport, this->m_fdinfo->get_l4proto(), m_inspector->m_hostname_and_port_resolution_enabled);
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_SERVERPORT:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}

				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}

				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port);
			}
			else
			{
				return NULL;
			}
		}
		break;
	case TYPE_SERVERPROTO:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			uint16_t nport = 0;

			scap_fd_type evt_type = m_fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}
				nport = m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				nport = m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}
				nport = m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				nport = m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
			}
			else
			{
				return NULL;
			}

			m_tstr = "";
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				m_tstr = port_to_string(nport, this->m_fdinfo->get_l4proto(), m_inspector->m_hostname_and_port_resolution_enabled);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = port_to_string(nport, this->m_fdinfo->get_l4proto(), m_inspector->m_hostname_and_port_resolution_enabled);
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_LPORT:
	case TYPE_RPORT:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type != SCAP_FD_IPV4_SOCK &&
			   evt_type != SCAP_FD_IPV6_SOCK)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			bool is_local;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, m_tinfo);
			}
		        else
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv6addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip, m_tinfo);
			}

 	        if(is_local)
			{
				if(m_field_id == TYPE_LPORT || m_field_id == TYPE_LPROTO)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport);
					}
					else
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport);
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
					}
					else
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport);
					}
				}
			}
			else
			{
				if(m_field_id == TYPE_LPORT || m_field_id == TYPE_LPROTO)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
					}
					else
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport);
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport);
					}
					else
					{
						RETURN_EXTRACT_VAR(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport);
					}
				}
			}
		}
		break;

	case TYPE_LPROTO:
	case TYPE_RPROTO:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type != SCAP_FD_IPV4_SOCK &&
			   evt_type != SCAP_FD_IPV6_SOCK)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			int16_t nport = 0;

			bool is_local;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, m_tinfo);
			}
		        else
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv6addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip, m_tinfo);
			}

                        if(is_local)
			{
				if(m_field_id == TYPE_LPORT || m_field_id == TYPE_LPROTO)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						nport = m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
					}
					else
					{
						nport = m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport;
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						nport = m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
					}
					else
					{
						nport = m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;
					}
				}
			}
			else
			{
				if(m_field_id == TYPE_LPORT || m_field_id == TYPE_LPROTO)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						nport = m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
					}
					else
					{
						nport = m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						nport = m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
					}
					else
					{
						nport = m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport;
					}

				}
			}

			m_tstr = port_to_string(nport, this->m_fdinfo->get_l4proto(), m_inspector->m_hostname_and_port_resolution_enabled);
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;

	case TYPE_L4PROTO:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			scap_l4_proto l4p = m_fdinfo->get_l4proto();

			switch(l4p)
			{
			case SCAP_L4_TCP:
				m_tstr = "tcp";
				break;
			case SCAP_L4_UDP:
				m_tstr = "udp";
				break;
			case SCAP_L4_ICMP:
				m_tstr = "icmp";
				break;
			case SCAP_L4_RAW:
				m_tstr = "raw";
				break;
			default:
				m_tstr = "<NA>";
				break;
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_IS_SERVER:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				m_tbool = true;
			}
			else if(m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				m_tbool =
					m_inspector->get_ifaddr_list().is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, m_tinfo);
			}
			else if(m_fdinfo->m_type == SCAP_FD_IPV6_SOCK)
			{
				m_tbool =
					m_inspector->get_ifaddr_list().is_ipv6addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip, m_tinfo);
			}
			else
			{
				m_tbool = false;
			}

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_SOCKFAMILY:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->m_type == SCAP_FD_IPV4_SOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SOCK ||
			   m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				m_tstr = "ip";
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else if(m_fdinfo->m_type == SCAP_FD_UNIX_SOCK)
			{
				m_tstr = "unix";
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
		break;
	case TYPE_UID:
		{
			if(m_tinfo == nullptr)
			{
				return NULL;
			}

			m_tstr = to_string(m_tinfo->m_tid) + to_string(m_tinfo->m_lastevent_fd);
			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_IS_CONNECTED:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_tbool = m_fdinfo->is_socket_connected();

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_NAME_CHANGED:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_tbool = evt->fdinfo_name_changed();

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_DEV:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_tbool = m_fdinfo->get_device();

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_DEV_MAJOR:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_tbool = m_fdinfo->get_device_major();

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_DEV_MINOR:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_tbool = m_fdinfo->get_device_minor();

			RETURN_EXTRACT_VAR(m_tbool);
		}
		break;
	case TYPE_INO:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			m_conv_uint64 = m_fdinfo->get_ino();

			RETURN_EXTRACT_VAR(m_conv_uint64);
		}
		break;
	case TYPE_FDNAMERAW:
		{
		if(m_fdinfo == NULL)
		{
			return extract_from_null_fd(evt, len, sanitize_strings);
		}

		m_tstr = m_fdinfo->m_name_raw;
		remove_duplicate_path_separators(m_tstr);
		RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	default:
		ASSERT(false);
	}

	return NULL;
}

bool sinsp_filter_check_fd::compare_ip(sinsp_evt *evt)
{
	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_fdinfo != NULL)
	{
		scap_fd_type evt_type = m_fdinfo->m_type;

		if(evt_type == SCAP_FD_IPV4_SOCK)
		{
			if(m_cmpop == CO_EQ || m_cmpop == CO_IN)
			{
				if(flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip) ||
					flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip))
				{
					return true;
				}
			}
			else if(m_cmpop == CO_NE)
			{
				if(flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip) &&
					flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip))
				{
					return true;
				}
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
		else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			if(m_cmpop == CO_EQ || m_cmpop == CO_NE || m_cmpop == CO_IN)
			{
				return flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip);
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
		else if(evt_type == SCAP_FD_IPV6_SOCK)
		{
			if(m_cmpop == CO_EQ || m_cmpop == CO_IN)
			{
				if(flt_compare(m_cmpop, PT_IPV6ADDR, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip) ||
					flt_compare(m_cmpop, PT_IPV6ADDR, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip))
				{
					return true;
				}
			}
			else if(m_cmpop == CO_NE)
			{
				if(flt_compare(m_cmpop, PT_IPV6ADDR, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip) &&
					flt_compare(m_cmpop, PT_IPV6ADDR, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip))
				{
					return true;
				}
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
		else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			if(m_cmpop == CO_EQ || m_cmpop == CO_NE || m_cmpop == CO_IN)
			{
				return flt_compare(m_cmpop, PT_IPV6ADDR, &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip);
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
	}

	return false;
}

bool sinsp_filter_check_fd::compare_net(sinsp_evt *evt)
{
	if(!extract_fd(evt) || m_fdinfo == nullptr)
	{
		return false;
	}

	bool sip_cmp = false;
	bool dip_cmp = false;

	switch (m_fdinfo->m_type)
	{
	case SCAP_FD_IPV4_SERVSOCK:
		return flt_compare_ipv4net(m_cmpop, m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip, (ipv4net*)filter_value_p());

	case SCAP_FD_IPV6_SERVSOCK:
		return flt_compare_ipv6net(m_cmpop, &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip, (ipv6net*)filter_value_p());

	case SCAP_FD_IPV4_SOCK:
		sip_cmp = flt_compare_ipv4net(m_cmpop, m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, (ipv4net*)filter_value_p());
		dip_cmp = flt_compare_ipv4net(m_cmpop, m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, (ipv4net*)filter_value_p());
		break;

	case SCAP_FD_IPV6_SOCK:
		sip_cmp = flt_compare_ipv6net(m_cmpop, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip, (ipv6net*)filter_value_p());
		dip_cmp = flt_compare_ipv6net(m_cmpop, &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip, (ipv6net*)filter_value_p());
		break;

	default:
		return false;
	}

	if(m_cmpop == CO_EQ || m_cmpop == CO_IN)
	{
		return sip_cmp || dip_cmp;
	}

	if(m_cmpop == CO_NE)
	{
		return sip_cmp && dip_cmp;
	}

	return false;
}

bool sinsp_filter_check_fd::compare_port(sinsp_evt *evt)
{
	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_fdinfo != NULL)
	{
		uint16_t* sport;
		uint16_t* dport;
		scap_fd_type evt_type = m_fdinfo->m_type;

		if(evt_type == SCAP_FD_IPV4_SOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
			dport = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
		}
		else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
			dport = &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
		}
		else if(evt_type == SCAP_FD_IPV6_SOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport;
			dport = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;
		}
		else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
			dport = &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
		}
		else
		{
			return false;
		}

		switch(m_cmpop)
		{
		case CO_EQ:
			if(*sport == *(uint16_t*)filter_value_p() ||
				*dport == *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;
		case CO_NE:
			if(*sport != *(uint16_t*)filter_value_p() &&
				*dport != *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;
		case CO_LT:
			if(*sport < *(uint16_t*)filter_value_p() ||
				*dport < *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;
		case CO_LE:
			if(*sport <= *(uint16_t*)filter_value_p() ||
				*dport <= *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;
		case CO_GT:
			if(*sport > *(uint16_t*)filter_value_p() ||
				*dport > *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;
		case CO_GE:
			if(*sport >= *(uint16_t*)filter_value_p() ||
				*dport >= *(uint16_t*)filter_value_p())
			{
				return true;
			}
			break;

		case CO_IN:
			if(flt_compare(m_cmpop,
				       PT_PORT,
				       sport,
				       sizeof(*sport)) ||
			   flt_compare(m_cmpop,
				       PT_PORT,
				       dport,
				       sizeof(*dport)))
			{
				return true;
			}
			break;
		default:
			throw sinsp_exception("filter error: unsupported port comparison operator");
		}
	}

	return false;
}

bool sinsp_filter_check_fd::compare_domain(sinsp_evt *evt)
{
	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_fdinfo != NULL)
	{
		scap_fd_type evt_type = m_fdinfo->m_type;
		if(evt_type != SCAP_FD_IPV4_SOCK &&
		   evt_type != SCAP_FD_IPV6_SOCK)
		{
			return false;
		}

		if(m_fdinfo->is_role_none())
		{
			return false;
		}

		uint32_t *addr;
		if(m_field_id == TYPE_CLIENTIP_NAME)
		{
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
			}
			else
			{
				addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0];
			}
		}
		else if(m_field_id == TYPE_SERVERIP_NAME)
		{
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
			}
			else
			{
				addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0];
			}
		}
		else
		{
			bool is_local;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, m_tinfo);
			}
			else
			{
				is_local = m_inspector->get_ifaddr_list().is_ipv6addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip, m_tinfo);
			}

			if(is_local)
			{
				if(m_field_id == TYPE_LIP_NAME)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
					}
					else
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0];
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
					}
					else
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0];
					}
				}
			}
			else
			{
				if(m_field_id == TYPE_LIP_NAME)
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
					}
					else
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b[0];
					}
				}
				else
				{
					if(evt_type == SCAP_FD_IPV4_SOCK)
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
					}
					else
					{
						addr = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b[0];
					}
				}
			}
		}

		uint64_t ts = evt->get_ts();

		if(m_cmpop == CO_IN)
		{
			for (uint16_t i=0; i < m_val_storages.size(); i++)
			{
				if(sinsp_dns_manager::get().match((const char *)filter_value_p(i), (evt_type == SCAP_FD_IPV6_SOCK)? AF_INET6 : AF_INET, addr, ts))
				{
					return true;
				}
			}

			return false;
		}
		else if(m_cmpop == CO_EQ)
		{
			return sinsp_dns_manager::get().match((const char *)filter_value_p(), (evt_type == SCAP_FD_IPV6_SOCK)? AF_INET6 : AF_INET, addr, ts);
		}
		else if(m_cmpop == CO_NE)
		{
			return !sinsp_dns_manager::get().match((const char *)filter_value_p(), (evt_type == SCAP_FD_IPV6_SOCK)? AF_INET6 : AF_INET, addr, ts);
		}
		else
		{
			throw sinsp_exception("filter error: fd.*ip.name filter only supports '=' and '!=' operators");
		}
	}

	return false;
}

bool sinsp_filter_check_fd::extract_fd(sinsp_evt *evt)
{
	ppm_event_flags eflags = evt->get_info_flags();

	//
	// Make sure this is an event that creates or consumes an fd
	//
	if(eflags & (EF_CREATES_FD | EF_USES_FD | EF_DESTROYS_FD))
	{
		//
		// This is an fd-related event, get the thread info and the fd info
		//
		m_tinfo = evt->get_thread_info();
		if(m_tinfo == NULL)
		{
			return false;
		}

		if (m_argid != -1)
		{
			m_fdinfo = m_tinfo->get_fd(m_argid);
		}
		else
		{
			m_fdinfo = evt->get_fd_info();

			if (m_fdinfo == NULL && m_tinfo->m_lastevent_fd != -1)
			{
				m_fdinfo = m_tinfo->get_fd(m_tinfo->m_lastevent_fd);
			}
		}
		// We'll check if fd is null below
	}
	else
	{
		return false;
	}

	return true;
}

bool sinsp_filter_check_fd::compare(sinsp_evt *evt)
{
	//
	// Some fields are filter only and therefore get a special treatment
	//
	if(m_field_id == TYPE_IP)
	{
		return compare_ip(evt);
	}
	else if(m_field_id == TYPE_PORT || m_field_id == TYPE_PROTO)
	{
		return compare_port(evt);
	}
	else if(m_field_id == TYPE_NET)
	{
		return compare_net(evt);
	}
	else if(m_field_id == TYPE_FDTYPES)
	{
		m_extracted_values.clear();
		if(!extract_cached(evt, m_extracted_values, false))
		{
			return false;
		}
		return flt_compare(m_cmpop, m_info.m_fields[m_field_id].m_type, m_extracted_values);
	}

	//
	// Standard extract-based fields
	//
	uint32_t len = 0;
	bool sanitize_strings = false;
	// note: this uses the single-value extract because this filtercheck
	// class does not support multi-valued extraction
	uint8_t* extracted_val = extract(evt, &len, sanitize_strings);

	if(extracted_val == NULL)
	{
		// optimization for *_NAME fields
		// the first time we will call compare_domain, the next ones
		// we will the able to extract and use flt_compare
		if(m_field_id == TYPE_CLIENTIP_NAME ||
		   m_field_id == TYPE_SERVERIP_NAME ||
		   m_field_id == TYPE_LIP_NAME ||
		   m_field_id == TYPE_RIP_NAME)
		{
			return compare_domain(evt);
		}

		return false;
	}

	return flt_compare(m_cmpop,
			   m_info.m_fields[m_field_id].m_type,
			   extracted_val,
			   len);
}
