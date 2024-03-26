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

#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <list>
#include <mutex>

#ifndef HELPER_32
#include <gtest/gtest.h>
#endif

#define SERVER_PORT 3555
#define SERVER_PORT_STR "3555"
#define FALSE 0

typedef enum iotype
{
	READWRITE,
	SENDRECEIVE,
	READVWRITEV
} iotype;

class std_event
{
public:
	void set()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_is_set = true;
		m_cond.notify_one();
	}
	void wait()
	{
		std::unique_lock<std::mutex> lock(m_mutex);
		if (m_is_set)
		{
			return;
		}
		else
		{
			m_cond.wait(lock, [this]() { return m_is_set; });
		}
	}

private:
	std::mutex m_mutex;
	std::condition_variable m_cond;
	bool m_is_set{false};
};

class tcp_server
{
public:
	tcp_server(iotype iot,
	           bool wait_for_signal_to_continue = false,
	           bool use_shutdown = false,
	           bool use_accept4 = false,
	           uint32_t ntransactions = 1,
	           bool exit_no_close = false)
	{
		m_iot = iot;
		m_wait_for_signal_to_continue = wait_for_signal_to_continue;
		m_use_shutdown = use_shutdown;
		m_use_accept4 = use_accept4;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	void run()
	{
		int servSock;
		int clntSock;
		struct sockaddr_in server_address;
		struct sockaddr_in client_address;
		unsigned int client_len;
		uint32_t j;
		int port = (m_exit_no_close) ? SERVER_PORT + 1 : SERVER_PORT;

		m_tid = syscall(SYS_gettid);

		/* Create socket for incoming connections */
		if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			perror("socket() failed");
			return;
		}

		/* Construct local address structure */
		memset(&server_address, 0, sizeof(server_address)); /* Zero out structure */
		server_address.sin_family = AF_INET;                /* Internet address family */
		server_address.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
		server_address.sin_port = htons(port);              /* Local port */

		int yes = 1;
		if (setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		{
#ifdef FAIL
			FAIL() << "setsockopt() failed";
#endif
		}

		/* Bind to the local address */
		if (::bind(servSock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
		{
#ifdef FAIL
			FAIL() << "bind() failed";
#endif
			return;
		}
		/* Mark the socket so it will listen for incoming connections */
		if (listen(servSock, 1) < 0)
		{
			close(servSock);
#ifdef FAIL
			FAIL() << "listen() failed";
#endif
			return;
		}
		std::cout << "SERVER UP" << std::endl;
		do
		{
			/* Set the size of the in-out parameter */
			client_len = sizeof(client_address);
			signal_ready();

			/* Wait for a client to connect */
			if (m_use_accept4)
			{
				if ((clntSock =
				         accept4(servSock, (struct sockaddr*)&client_address, &client_len, 0)) < 0)
				{
					close(servSock);
#ifdef FAIL
					FAIL() << "accept() failed";
#endif
					break;
				}
			}
			else
			{
				if ((clntSock = accept(servSock, (struct sockaddr*)&client_address, &client_len)) <
				    0)
				{
					close(servSock);
#ifdef FAIL
					FAIL() << "accept() failed";
#endif
					break;
				}
			}

			/* clntSock is connected to a client! */
			wait_for_continue();
			char echoBuffer[1024]; /* Buffer for echo string */
			int recvMsgSize;       /* Size of received message */
			for (j = 0; j < m_ntransactions; j++)
			{
				if (m_iot == SENDRECEIVE)
				{
					if ((recvMsgSize = recv(clntSock, echoBuffer, sizeof(echoBuffer), 0)) < 0)
					{
#ifdef FAIL
						FAIL() << "recv() failed";
#endif
						break;
					}

					if (send(clntSock, echoBuffer, recvMsgSize, 0) != recvMsgSize)
					{
#ifdef FAIL
						FAIL() << "send() failed";
#endif
						break;
					}
				}
				else if (m_iot == READWRITE || m_iot == READVWRITEV)
				{
					if ((recvMsgSize = read(clntSock, echoBuffer, sizeof(echoBuffer))) < 0)
					{
#ifdef FAIL
						FAIL() << "recv() failed";
#endif
						break;
					}

					if (write(clntSock, echoBuffer, recvMsgSize) != recvMsgSize)
					{
#ifdef FAIL
						FAIL() << "send() failed";
#endif
						break;
					}
				}
			}

			if (m_exit_no_close)
			{
				return;
			}

			if (m_use_shutdown)
			{
#ifdef ASSERT_EQ
				ASSERT_EQ(0, shutdown(clntSock, SHUT_WR));
#endif
			}
			else
			{
				close(clntSock); /* Close client socket */
			}
			break;
		} while (0);

		if (m_use_shutdown)
		{
#ifdef ASSERT_EQ
			ASSERT_EQ(0, shutdown(servSock, SHUT_RDWR));
#endif
		}
		else
		{
			close(servSock);
		}
	}

	void wait_till_ready() { m_ready.wait(); }

	void signal_continue() { m_continue.set(); }

	int64_t get_tid() { return m_tid; }

private:
	void signal_ready() { m_ready.set(); }

	void wait_for_continue()
	{
		if (m_wait_for_signal_to_continue)
		{
			m_continue.wait();
		}
	}

	std_event m_ready;
	std_event m_continue;
	bool m_wait_for_signal_to_continue;
	int64_t m_tid;
	iotype m_iot;
	bool m_use_shutdown;
	bool m_use_accept4;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

class tcp_client
{
public:
	tcp_client(uint32_t server_ip_address,
	           iotype iot,
	           const std::string& payload = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM",
	           bool on_thread = false,
	           uint32_t ntransactions = 1,
	           bool exit_no_close = false)
	{
		m_server_ip_address = server_ip_address;
		m_iot = iot;
		m_payload = payload;
		m_on_thread = on_thread;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	void run()
	{
		int sock;
		struct sockaddr_in server_address;
		char buffer[m_payload.size() + 1];
		int bytes_received;
		uint32_t j;
		int port = (m_exit_no_close) ? SERVER_PORT + 1 : SERVER_PORT;

		m_tid = syscall(SYS_gettid);

		/* Create a reliable, stream socket using TCP */
		if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
#ifdef FAIL
			FAIL() << "socket() failed";
#endif
			signal_ready();
			return;
		}

		/* Construct the server address structure */
		memset(&server_address, 0, sizeof(server_address));   /* Zero out structure */
		server_address.sin_family = AF_INET;                  /* Internet address family */
		server_address.sin_addr.s_addr = m_server_ip_address; /* Server IP address */
		server_address.sin_port = htons(port);                /* Server port */

		/* Establish the connection to the server */
		if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
		{
#ifdef FAIL
			FAIL() << "connect() failed";
#endif
			signal_ready();
			return;
		}
		signal_ready();
		wait_for_continue();

		for (j = 0; j < m_ntransactions; j++)
		{
			/* Send the string to the server */
			if (m_iot == SENDRECEIVE)
			{
				if (send(sock, m_payload.c_str(), m_payload.length(), 0) !=
				    (ssize_t)m_payload.length())
				{
					close(sock);
#ifdef FAIL
					FAIL() << "send() sent a different number of bytes than expected";
#endif
					return;
				}

				if ((bytes_received = recv(sock, buffer, m_payload.length(), 0)) <= 0)
				{
					close(sock);
#ifdef FAIL
					FAIL() << "recv() failed or connection closed prematurely";
#endif
					return;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
#ifdef ASSERT_STREQ
				ASSERT_STREQ(m_payload.c_str(), buffer);
#endif
			}
			else if (m_iot == READWRITE)
			{
				if (write(sock, m_payload.c_str(), m_payload.length()) !=
				    (ssize_t)m_payload.length())
				{
					close(sock);
#ifdef FAIL
					FAIL() << "send() sent a different number of bytes than expected";
#endif
					return;
				}

				if ((bytes_received = read(sock, buffer, m_payload.length())) <= 0)
				{
					close(sock);
#ifdef FAIL
					FAIL() << "recv() failed or connection closed prematurely";
#endif
					return;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
#ifdef ASSERT_STREQ
				ASSERT_STREQ(m_payload.c_str(), buffer);
#endif
			}
			else if (m_iot == READVWRITEV)
			{
				int wv_count;
				char msg1[m_payload.length() / 3 + 1];
				char msg2[m_payload.length() / 3 + 1];
				char msg3[m_payload.length() / 3 + 1];
				struct iovec wv[3];

				memcpy(msg1,
				       m_payload.substr(0, m_payload.length() / 3).c_str(),
				       m_payload.length() / 3);
				memcpy(msg2,
				       m_payload.substr(m_payload.length() / 3, m_payload.length() * 2 / 3).c_str(),
				       m_payload.length() / 3);
				memcpy(msg3,
				       m_payload.substr(m_payload.length() * 2 / 3, m_payload.length()).c_str(),
				       m_payload.length() / 3);

				wv[0].iov_base = msg1;
				wv[1].iov_base = msg2;
				wv[2].iov_base = msg3;
				wv[0].iov_len = m_payload.length() / 3;
				wv[1].iov_len = m_payload.length() / 3;
				wv[2].iov_len = m_payload.length() / 3;
				wv_count = 3;

				if (writev(sock, wv, wv_count) != (ssize_t)m_payload.length())
				{
					close(sock);
#ifdef FAIL
					FAIL() << "send() sent a different number of bytes than expected";
#endif
					return;
				}

				if ((bytes_received = readv(sock, wv, wv_count)) <= 0)
				{
					close(sock);
#ifdef FAIL
					FAIL() << "recv() failed or connection closed prematurely";
#endif
					return;
				}
			}
		}

		if (m_exit_no_close)
		{
			return;
		}

		close(sock);
	}

	void wait_till_ready() { m_ready.wait(); }

	void signal_continue() { m_continue.set(); }

	int64_t get_tid() { return m_tid; }

private:
	void signal_ready() { m_ready.set(); }

	void wait_for_continue()
	{
		if (m_on_thread)
		{
			m_continue.wait();
		}
	}

	uint32_t m_server_ip_address;
	iotype m_iot;
	std_event m_ready;
	std_event m_continue;
	int64_t m_tid;
	bool m_on_thread;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
	std::string m_payload;
};
