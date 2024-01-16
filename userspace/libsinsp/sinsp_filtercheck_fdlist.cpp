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

#include <libsinsp/sinsp_filtercheck_fdlist.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

using namespace std;

#define RETURN_EXTRACT_STRING(x) do {  \
        *len = (x).size();             \
        return (uint8_t*) (x).c_str(); \
} while(0)

static const filtercheck_field_info sinsp_filter_check_fdlist_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_ID, "fdlist.nums", "FD Numbers", "for poll events, this is a comma-separated list of the FD numbers in the 'fds' argument, returned as a string."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fdlist.names", "FD Names", "for poll events, this is a comma-separated list of the FD names in the 'fds' argument, returned as a string."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fdlist.cips", "FD Client Addresses", "for poll events, this is a comma-separated list of the client IP addresses in the 'fds' argument, returned as a string."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fdlist.sips", "FD Source Addresses", "for poll events, this is a comma-separated list of the server IP addresses in the 'fds' argument, returned as a string."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fdlist.cports", "FD Client Ports", "for TCP/UDP FDs, for poll events, this is a comma-separated list of the client TCP/UDP ports in the 'fds' argument, returned as a string."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fdlist.sports", "FD Source Ports", "for poll events, this is a comma-separated list of the server TCP/UDP ports in the 'fds' argument, returned as a string."},
};

sinsp_filter_check_fdlist::sinsp_filter_check_fdlist()
{
	m_info.m_name = "fdlist";
	m_info.m_desc = "Poll event related fields.";
	m_info.m_fields = sinsp_filter_check_fdlist_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_fdlist_fields) / sizeof(sinsp_filter_check_fdlist_fields[0]);
	m_info.m_flags = filter_check_info::FL_NONE;
}

sinsp_filter_check* sinsp_filter_check_fdlist::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_fdlist();
}

uint8_t* sinsp_filter_check_fdlist::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	ASSERT(evt);
	const sinsp_evt_param *parinfo;

	uint16_t etype = evt->get_type();

	if(etype == PPME_SYSCALL_POLL_E || etype == PPME_SYSCALL_PPOLL_E)
	{
		parinfo = evt->get_param(0);
	}
	else if(etype == PPME_SYSCALL_POLL_X || etype == PPME_SYSCALL_PPOLL_X)
	{
		parinfo = evt->get_param(1);
	}
	else
	{
		return NULL;
	}

	uint32_t j = 0;
	const char* payload = parinfo->m_val;
	uint16_t nfds = *(uint16_t *)payload;
	uint32_t pos = 2;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(!tinfo)
	{
		return NULL;
	}

	m_strval.clear();

	for(j = 0; j < nfds; j++)
	{
		bool add_comma = true;
		int64_t fd = *(int64_t *)(payload + pos);

		sinsp_fdinfo *fdinfo = tinfo ? tinfo->get_fd(fd) : NULL;

		switch(m_field_id)
		{
		case TYPE_FDNUMS:
		{
			m_strval += to_string(fd);
		}
		break;
		case TYPE_FDNAMES:
		{
			if(fdinfo != NULL)
			{
				if(fdinfo->m_name != "")
				{
					m_strval += fdinfo->m_name;
				}
				else
				{
					m_strval += "<NA>";
				}
			}
			else
			{
				m_strval += "<NA>";
			}
		}
		break;
		case TYPE_CLIENTIPS:
		{
			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
				{
					inet_ntop(AF_INET, &fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
				{
					inet_ntop(AF_INET6, fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip.m_b, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
			}

			add_comma = false;
		}
		break;
		case TYPE_SERVERIPS:
		{
			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
				{
					inet_ntop(AF_INET, &fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
				{
					inet_ntop(AF_INET6, fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK)
				{
					inet_ntop(AF_INET, &fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
				{
					inet_ntop(AF_INET, &fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip.m_b, m_addrbuff, sizeof(m_addrbuff));
					m_strval += m_addrbuff;
					break;
				}
			}

			add_comma = false;
		}
		break;
		case TYPE_CLIENTPORTS:
		{
			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
				{
					m_strval += to_string(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport);
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
				{
					m_strval += to_string(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport);
					break;
				}
			}

			add_comma = false;
		}
		case TYPE_SERVERPORTS:
		{
			if(fdinfo != NULL)
			{
				if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
				{
					m_strval += to_string(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
					break;
				}
				else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
				{
					m_strval += to_string(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport);
					break;
				}
			}

			add_comma = false;
		}
		break;
		default:
			ASSERT(false);
		}

		if(j < nfds && add_comma)
		{
			m_strval += ",";
		}

		pos += 10;
	}

	if(m_strval.size() != 0)
	{
		if(m_strval.back() == ',')
		{
			m_strval = m_strval.substr(0, m_strval.size() - 1);
		}

		RETURN_EXTRACT_STRING(m_strval);
	}
	else
	{
		return NULL;
	}
}
