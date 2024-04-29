// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "event_capture.h"
#include "subprocess.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <libsinsp/event.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <netinet/in.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>

#include <algorithm>
#include <cassert>
#include <list>
#include <tuple>

#include <libsinsp/sinsp_int.h>

#define NAME "/tmp/python_unix_sockets_example"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH (sizeof(PAYLOAD) - 1)
#define FALSE 0

inline void parse_tuple(const std::string& tuple,
						std::string& srcstr,
						std::string& dststr, bool shift = false)
{
	std::string token;
	std::stringstream ss(tuple);
	std::vector<std::string> tst;

	int base = shift? 1 : 0;

	while (std::getline(ss, token, '>')) {
		tst.push_back(token);
	}

	int size = shift? 3 : 2;
	EXPECT_EQ(size, (int)tst.size());

	srcstr = tst[base].substr(0, tst[base].size() - 1);
	dststr = tst[base+1];
}

inline bool ends_with(const std::string& value, const std::string& ending)
{
	if (ending.size() > value.size()) return false;
	return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

TEST_F(sys_call_test, unix_client_server)
{
	int32_t callnum = 0;
	bool first_connect_or_accept_seen = true;
	std::string sport;
	std::string src_addr;
	std::string dest_addr;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		sinsp_threadinfo* ti = evt->get_thread_info(false);
		if (ti)
		{
			if (ti->get_comm() == "python2" && ti->m_args.size() >= 1)
			{
				return ends_with(ti->m_args[0],"unix_client_server.py") ||
				       ends_with(ti->m_args[0],"unix_client_server.py");
			}
		}

		return false;
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [](concurrent_object_handle<sinsp> inspector)
	{
		subprocess server("python2", {LIBSINSP_TEST_RESOURCES_PATH "/unix_client_server.py", "server"});

		server.wait_for_start();

		subprocess client("python2", {LIBSINSP_TEST_RESOURCES_PATH "/unix_client_server.py", "client"});
		server.wait();
		client.wait();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;

		//std::cout << evt->get_name() << std::endl;

		if (evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			std::string tuple = evt->get_param_value_str("tuple");
			std::string addrs = tuple.substr(0, tuple.find(" "));
			std::string file = tuple.substr(tuple.find(" ") + 1);

			EXPECT_EQ(NAME, file);

			std::string srcstr;
			std::string dststr;
			parse_tuple(tuple, srcstr, dststr);

			EXPECT_NE("0000000000000000", srcstr);
			EXPECT_NE("0000000000000000", dststr);

			//
			// connect() and accept() can return
			// in a different order
			//
			if (first_connect_or_accept_seen)
			{
				first_connect_or_accept_seen = false;
				src_addr = srcstr.substr(1);
				dest_addr = dststr;
			}
			else
			{
				EXPECT_EQ(src_addr, srcstr.substr(1));
				EXPECT_EQ(dest_addr, dststr);
			}

			callnum++;
		}
		else if ((evt->get_type() == PPME_SOCKET_ACCEPT_5_X) ||
		         (evt->get_type() == PPME_SOCKET_ACCEPT4_6_X))
		{
			std::string tuple = evt->get_param_value_str("tuple");
			std::string addrs = tuple.substr(0, tuple.find(" "));
			std::string file = tuple.substr(tuple.find(" ") + 1);

			EXPECT_EQ(NAME, file);

			std::string srcstr;
			std::string dststr;
			parse_tuple(tuple, srcstr, dststr);

			EXPECT_NE("0000000000000000", srcstr);
			EXPECT_NE("0000000000000000", dststr);

			//
			// connect() and accept() can return
			// in a different order
			//
			if (first_connect_or_accept_seen)
			{
				first_connect_or_accept_seen = false;
				src_addr = srcstr.substr(1);
				dest_addr = dststr;
			}
			else
			{
				EXPECT_EQ(src_addr, srcstr.substr(1));
				EXPECT_EQ(dest_addr, dststr);
			}

			std::string fdtuple = evt->get_param_value_str("tuple");
			std::string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
			std::string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

			EXPECT_EQ(NAME, fdfile);

			std::string fdsrcstr;
			std::string fddststr;
			parse_tuple(tuple, fdsrcstr, fddststr);

			EXPECT_NE("0000000000000000", fdsrcstr);
			EXPECT_NE("0000000000000000", fddststr);

			callnum++;
		}

		if (callnum < 1)
		{
			return;
		}

		//
		// 32bit (and s390x) uses send() and recv(), while 64bit
		// uses sendto() and recvfrom() and sets the address to NULL
		//
		if (evt->get_type() == PPME_SOCKET_SEND_E || evt->get_type() == PPME_SOCKET_RECV_E ||
		    evt->get_type() == PPME_SOCKET_SENDTO_E || evt->get_type() == PPME_SOCKET_RECVFROM_E)
		{
			if (((evt->get_type() == PPME_SOCKET_RECVFROM_X) ||
			     (evt->get_type() == PPME_SOCKET_RECVFROM_X)) &&
			    (evt->get_param_value_str("tuple") != ""))
			{
				EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
			}

			std::string fdtuple = evt->get_param_value_str("fd");
			std::string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
			std::string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

			EXPECT_EQ(NAME, fdfile);

			std::string fdsrcstr;
			std::string fddststr;
			parse_tuple(fdtuple, fdsrcstr, fddststr, true);

			EXPECT_NE("0", fdsrcstr);
			EXPECT_NE("0", fddststr);

			callnum++;
		}
		else if ((evt->get_type() == PPME_SOCKET_RECV_X) ||
		         (evt->get_type() == PPME_SOCKET_RECVFROM_X))
		{
			if (evt->get_type() == PPME_SOCKET_RECVFROM_X)
			{
				if (callnum == 5)
 				{
 					std::string tuple = evt->get_param_value_str("tuple");
 					std::string addrs = tuple.substr(0, tuple.find(" "));
 					std::string file = tuple.substr(tuple.find(" ") + 1);

 					EXPECT_EQ(NAME, file);

					std::string srcstr;
					std::string dststr;
					parse_tuple(tuple, srcstr, dststr);

 					EXPECT_NE("0000000000000000", srcstr);
 					EXPECT_NE("0000000000000000", dststr);
 				}
			}
			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}
	};

	//
	// OUTPUT VALDATION
	//
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_FALSE(first_connect_or_accept_seen);
	EXPECT_EQ(8, callnum);
}

