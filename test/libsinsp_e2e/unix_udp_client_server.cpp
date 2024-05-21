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

#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>

#include <libsinsp/sinsp_int.h>

#define NAME "/tmp/python_unix_udp_sockets_example"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

class unix_udp_server
{
public:
	unix_udp_server(bool use_recvfrom) {
		m_use_recvfrom = use_recvfrom;
		m_server_ready = false;
	}

	void run()
	{
		int sock;
		struct sockaddr_un name;
		struct sockaddr_un caddr;
		socklen_t address_length = sizeof(struct sockaddr_un);
		char buf[1024];

		m_tid = syscall(SYS_gettid);

		/* Create socket from which to read. */
		sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0)
		{
			perror("opening datagram socket");
			exit(1);
		}

		/* Create name. */
		name.sun_family = AF_UNIX;
		strcpy(name.sun_path, NAME);

		if (::bind(sock, (struct sockaddr*)&name, SUN_LEN(&name)))
		{
			perror("binding name to datagram socket");
			exit(1);
		}

		{
			std::unique_lock<std::mutex> lock(m_mutex);
			m_server_ready = true;
			m_condition_server_ready.notify_one();
		}

		/* Read from the socket. */
		if (m_use_recvfrom)
		{
			recvfrom(sock, buf, 1024, 0, (struct sockaddr*)&caddr, &address_length);

			recvfrom(sock, buf, 1024, 0, (struct sockaddr*)&caddr, &address_length);
		}
		else
		{
			ASSERT_TRUE(read(sock, buf, 1024) >= 0);

			ASSERT_TRUE(read(sock, buf, 1024) >= 0);
		}

		close(sock);

		unlink(NAME);
	}

	void wait_for_server_ready()
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		m_condition_server_ready.wait(lock, [this]() {
			return m_server_ready;
		});
		m_server_ready = false;
	}

	int64_t get_tid() { return m_tid; }

private:
	std::mutex m_mutex;
	std::condition_variable m_condition_server_ready;
	bool m_server_ready;
	int64_t m_tid;
	bool m_use_recvfrom;
};

class unix_udp_client
{
public:
	void run()
	{
		int sock;
		struct sockaddr_un name;

		/* Create socket on which to send. */
		sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (sock < 0)
		{
			perror("opening datagram socket");
			exit(1);
		}

		/* Construct name of socket to send to. */
		name.sun_family = AF_UNIX;
		strcpy(name.sun_path, NAME);
		/* Send message. */

		sendto(sock,
		       PAYLOAD,
		       sizeof(PAYLOAD) - 1,
		       0,
		       (struct sockaddr*)&name,
		       sizeof(struct sockaddr_un));

		sendto(sock,
		       PAYLOAD,
		       sizeof(PAYLOAD) - 1,
		       0,
		       (struct sockaddr*)&name,
		       sizeof(struct sockaddr_un));

		close(sock);
	}

private:
};

inline void parse_tuple(const std::string& tuple,
						std::string& srcstr,
						std::string& dststr, int check_size)
{
	std::string token;
	std::stringstream ss(tuple);
	std::vector<std::string> tst;

	while (std::getline(ss, token, '>')) {
		tst.push_back(token);
	}

	EXPECT_EQ(check_size, (int)tst.size());

	srcstr = tst[0].substr(0, tst[0].size() - 1);
	dststr = tst[1];
}

TEST_F(sys_call_test, unix_udp_client_server_read)
{
	std::thread server_thread;
	std::shared_ptr<unix_udp_server> server = std::make_shared<unix_udp_server>(false);
	int32_t callnum = 0;
	std::string sport;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == server->get_tid() || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		server_thread = std::thread(&unix_udp_server::run, server);
		server->wait_for_server_ready();

		unix_udp_client client;
		client.run();
		server_thread.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;
		if (evt->get_type() == PPME_SOCKET_BIND_X)
		{
			std::string ttuple = evt->get_param_value_str("addr");

			EXPECT_EQ(NAME, ttuple);

			callnum++;
		}

		if (evt->get_type() == PPME_SOCKET_SENDTO_E)
		{
			std::string ttuple = evt->get_param_value_str("tuple");
			std::string taddrs = ttuple.substr(0, ttuple.find(" "));
			std::string tfile = ttuple.substr(ttuple.find(" ") + 1);

			EXPECT_EQ(NAME, tfile);

			std::string tsrcstr;
			std::string tdststr;
			parse_tuple(ttuple, tsrcstr, tdststr, 2);

			if (evt->get_tid() == server->get_tid())
			{
				EXPECT_NE("0", tsrcstr);
				EXPECT_EQ("0", tdststr);
			}
			else
			{
				EXPECT_EQ("0", tsrcstr);
				EXPECT_NE("0", tdststr);
			}

			std::string fdtuple = evt->get_param_value_str("fd");

			if (fdtuple.length() > 3)
			{
				std::string fdaddrs = fdtuple.substr(0, fdtuple.find(" "));
				std::string fdfile = fdtuple.substr(fdtuple.find(" ") + 1);

				EXPECT_EQ(NAME, fdfile);

				std::string fdsrcstr;
				std::string fddststr;
				parse_tuple(fdtuple, fdsrcstr, fddststr, 3);

				EXPECT_EQ('u', fdaddrs[1]);

				if (evt->get_tid() == server->get_tid())
				{
					EXPECT_NE("0", tsrcstr);
					EXPECT_EQ("0", tdststr);
				}
				else
				{
					EXPECT_EQ("0", tsrcstr);
					EXPECT_NE("0", tdststr);
				}
			}
			else
			{
				if (fdtuple.length() == 1)
				{
					EXPECT_EQ("u", fdtuple);
				}
			}

			if (evt->get_type() == PPME_SOCKET_SENDTO_X)
			{
				EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));
			}

			callnum++;
		}
		else if (evt->get_type() == PPME_SYSCALL_READ_E)
		{
			if (callnum < 1)
			{
				return;
			}

			std::string fdtuple = evt->get_param_value_str("fd");

			EXPECT_GT(fdtuple.length(), (unsigned int)1);

			if (fdtuple.length() > 1)
			{
				std::string ttype = fdtuple.substr(0, fdtuple.find(">"));
				std::string tfile = fdtuple.substr(fdtuple.find(">") + 1);

				EXPECT_EQ("<u", ttype);
				EXPECT_EQ(NAME, tfile);
			}

			callnum++;
		}
		else if (evt->get_type() == PPME_SYSCALL_READ_X)
		{
			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(7, callnum);
}
