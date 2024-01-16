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

#pragma once

#include <libsinsp/sinsp_filtercheck.h>

class sinsp_filter_check_fd : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUM = 0,
		TYPE_FDTYPE = 1,
		TYPE_FDTYPECHAR = 2,
		TYPE_FDNAME = 3,
		TYPE_DIRECTORY = 4,
		TYPE_FILENAME = 5,
		TYPE_IP = 6,
		TYPE_CLIENTIP = 7,
		TYPE_SERVERIP = 8,
		TYPE_LIP = 9,
		TYPE_RIP = 10,
		TYPE_PORT = 11,
		TYPE_CLIENTPORT = 12,
		TYPE_SERVERPORT = 13,
		TYPE_LPORT = 14,
		TYPE_RPORT = 15,
		TYPE_L4PROTO = 16,
		TYPE_SOCKFAMILY = 17,
		TYPE_IS_SERVER = 18,
		TYPE_UID = 19,
		TYPE_CONTAINERNAME = 20,
		TYPE_CONTAINERDIRECTORY = 21,
		TYPE_PROTO = 22,
		TYPE_CLIENTPROTO = 23,
		TYPE_SERVERPROTO = 24,
		TYPE_LPROTO = 25,
		TYPE_RPROTO = 26,
		TYPE_NET = 27,
		TYPE_CNET = 28,
		TYPE_SNET = 29,
		TYPE_LNET = 30,
		TYPE_RNET = 31,
		TYPE_IS_CONNECTED = 32,
		TYPE_NAME_CHANGED = 33,
		TYPE_CLIENTIP_NAME = 34,
		TYPE_SERVERIP_NAME = 35,
		TYPE_LIP_NAME = 36,
		TYPE_RIP_NAME = 37,
		TYPE_DEV = 38,
		TYPE_DEV_MAJOR = 39,
		TYPE_DEV_MINOR = 40,
		TYPE_INO = 41,
		TYPE_FDNAMERAW = 42,
		TYPE_FDTYPES = 43,
	};

	enum fd_type
	{
		FDT_NONE,
		FDT_FILE,
		FDT_SOCK,
		FDT_IPV4_SOCK,
		FDT_IPV6_SOCK,
		FDT_UNIX_SOCK,
		FDT_PIPE,
		FDT_EVENT,
		FDT_SIGNALFD,
		FDT_EVENTPOLL,
		FDT_INOTIFY,
		FDT_TIMERFD
	};

	sinsp_filter_check_fd();

	sinsp_filter_check* allocate_new() override;
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) override;
	bool extract(sinsp_evt*, OUT std::vector<extract_value_t>& values, bool sanitize_strings = true) override;
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;
	bool compare(sinsp_evt*) override;

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
	fd_type m_fd_type;
	std::string m_tstr;
	uint8_t m_tcstr[2];
	uint32_t m_tbool;
	int64_t m_argid;

	/* Used in extract helper to save uint64_t data */
	uint64_t m_conv_uint64;

private:
	int32_t extract_arg(std::string fldname, std::string val);
	uint8_t* extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings);
	bool extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings, bool fd_nameraw = false);
	bool extract_fd(sinsp_evt *evt);

	bool compare_ip(sinsp_evt *evt);
	bool compare_net(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare_domain(sinsp_evt *evt);
};
