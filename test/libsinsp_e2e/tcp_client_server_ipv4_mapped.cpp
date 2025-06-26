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
#include "sys_call_test.h"
#include "tcp_client_server.h"
#include "utils.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <libsinsp/event.h>
#include <netinet/in.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <algorithm>
#include <cassert>
#include <future>
#include <list>

#include <libsinsp/sinsp_int.h>

#define SERVER_PORT 3555
#define SERVER_PORT_STR "3555"
#define SERVER_PORT_NOCLOSE_STR "3557"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH sizeof(PAYLOAD)
#define FALSE 0

class tcp_server_ipv4m {
public:
	explicit tcp_server_ipv4m(iotype iot,
	                          bool use_shutdown = false,
	                          bool use_accept4 = false,
	                          uint32_t ntransactions = 1,
	                          bool exit_no_close = false) {
		m_tid = -1;
		m_iot = iot;
		m_use_shutdown = use_shutdown;
		m_use_accept4 = use_accept4;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	bool init() {
		struct sockaddr_in6 server_address;

		const int port = (m_exit_no_close) ? SERVER_PORT + 2 : SERVER_PORT;

		/* Create socket for incoming connections */
		if((m_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
			perror("socket() failed");
			return false;
		}

		/* Construct local address structure */
		memset(&server_address, 0, sizeof(server_address));
		server_address.sin6_family = AF_INET6;
		server_address.sin6_port = htons(port);
		server_address.sin6_addr = in6addr_any;

		int yes = 1;
		if(setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt() failed");
			return false;
		}

		/* Bind to the local address */
		if(::bind(m_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
			perror("bind() failed");
			return false;
		}
		/* Mark the socket so it will listen for incoming connections */
		if(listen(m_socket, 1) < 0) {
			perror("listen() failed");
			return false;
		}

		std::cout << "SERVER UP" << std::endl;
		return true;
	}

	int run() {
		struct sockaddr_in6 client_address;
		unsigned int client_len;
		m_tid = syscall(SYS_gettid);
		int error = 0;
		do {
			/* Set the size of the in-out parameter */
			client_len = sizeof(client_address);

			/* Wait for a client to connect */
			if(m_use_accept4) {
				if((m_cl_socket =
				            accept4(m_socket, (struct sockaddr*)&client_address, &client_len, 0)) <
				   0) {
					perror("accept() failed");
					error++;
					break;
				}
			} else {
				if((m_cl_socket =
				            accept(m_socket, (struct sockaddr*)&client_address, &client_len)) < 0) {
					perror("accept() failed");
					error++;
					break;
				}
			}

			/* m_cl_socket is connected to a client! */
			char echoBuffer[BUFFER_LENGTH]; /* Buffer for echo string */
			int recvMsgSize;                /* Size of received message */
			for(uint32_t j = 0; j < m_ntransactions; j++) {
				if(m_iot == SENDRECEIVE) {
					if((recvMsgSize = recv(m_cl_socket, echoBuffer, BUFFER_LENGTH, 0)) < 0) {
						perror("recv() failed");
						error++;
						break;
					}

					if(send(m_cl_socket, echoBuffer, recvMsgSize, 0) != recvMsgSize) {
						perror("send() failed");
						error++;
						break;
					}
				} else if(m_iot == READWRITE || m_iot == READVWRITEV) {
					if((recvMsgSize = read(m_cl_socket, echoBuffer, BUFFER_LENGTH)) < 0) {
						perror("recv() failed");
						error++;
						break;
					}

					if(write(m_cl_socket, echoBuffer, recvMsgSize) != recvMsgSize) {
						perror("send() failed");
						error++;
						break;
					}
				}
			}
		} while(0);

		if(error) {
			// Close the server socket so that client will be notified
			if(m_use_shutdown) {
				shutdown(m_socket, SHUT_RDWR);
			} else {
				close(m_socket);
			}
		} else {
			if(!m_exit_no_close) {
				if(m_use_shutdown) {
					if(m_cl_socket != -1) {
						shutdown(m_cl_socket, SHUT_WR);
					}
					if(m_socket != -1) {
						shutdown(m_socket, SHUT_RDWR);
					}
				} else {
					if(m_cl_socket != -1) {
						close(m_cl_socket);
					}
					if(m_socket != -1) {
						close(m_socket);
					}
				}
			}
		}
		return error;
	}

	int64_t get_tid() const { return m_tid; }

	void shutdown_server() {
		if(m_socket != -1) {
			shutdown(m_socket, SHUT_RDWR);
		}
	}

private:
	int m_socket = -1;
	int m_cl_socket = -1;
	int64_t m_tid;
	iotype m_iot;
	bool m_use_shutdown;
	bool m_use_accept4;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

class tcp_client_ipv4m {
public:
	tcp_client_ipv4m(uint32_t server_ip_address,
	                 iotype iot,
	                 uint32_t ntransactions = 1,
	                 bool exit_no_close = false) {
		m_tid = -1;
		m_server_ip_address = server_ip_address;
		m_iot = iot;
		m_ntransactions = ntransactions;
		m_exit_no_close = exit_no_close;
	}

	bool init() {
		struct sockaddr_in server_address;
		const int port = (m_exit_no_close) ? SERVER_PORT + 2 : SERVER_PORT;

		/* Create a reliable, stream socket using TCP */
		if((m_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			perror("socket() failed");
			return false;
		}

		/* Construct the server address structure */
		memset(&server_address, 0, sizeof(server_address));   /* Zero out structure */
		server_address.sin_family = AF_INET;                  /* Internet address family */
		server_address.sin_addr.s_addr = m_server_ip_address; /* Server IP address */
		server_address.sin_port = htons(port);                /* Server port */

		/* Establish the connection to the server */
		if(connect(m_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
			perror("connect() failed");
			return false;
		}

		std::cout << "CLIENT UP" << std::endl;
		return true;
	}

	int run() {
		char buffer[BUFFER_LENGTH];
		int payload_length;
		int bytes_received;
		uint32_t j;
		int error = 0;

		m_tid = syscall(SYS_gettid);

		payload_length = strlen(PAYLOAD); /* Determine input length */

		for(j = 0; j < m_ntransactions; j++) {
			/* Send the string to the server */
			if(m_iot == SENDRECEIVE) {
				if(send(m_socket, PAYLOAD, payload_length, 0) != payload_length) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = recv(m_socket, buffer, BUFFER_LENGTH - 1, 0)) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
				if(strcmp(PAYLOAD, buffer) != 0) {
					perror("SENDRECEIVE buffer mismatch, expected " PAYLOAD);
					error++;
					break;
				}
			} else if(m_iot == READWRITE) {
				if(write(m_socket, PAYLOAD, payload_length) != payload_length) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = read(m_socket, buffer, BUFFER_LENGTH - 1)) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}

				buffer[bytes_received] = '\0'; /* Terminate the string! */
				if(strcmp(PAYLOAD, buffer) != 0) {
					perror("READWRITE buffer mismatch, expected " PAYLOAD);
					error++;
					break;
				}
			} else if(m_iot == READVWRITEV) {
				std::string ps(PAYLOAD);
				int wv_count;
				char msg1[BUFFER_LENGTH / 3 + 1];
				char msg2[BUFFER_LENGTH / 3 + 1];
				char msg3[BUFFER_LENGTH / 3 + 1];
				struct iovec wv[3];

				memcpy(msg1, ps.substr(0, BUFFER_LENGTH / 3).c_str(), BUFFER_LENGTH / 3);
				memcpy(msg2,
				       ps.substr(BUFFER_LENGTH / 3, BUFFER_LENGTH * 2 / 3).c_str(),
				       BUFFER_LENGTH / 3);
				memcpy(msg3,
				       ps.substr(BUFFER_LENGTH * 2 / 3, BUFFER_LENGTH).c_str(),
				       BUFFER_LENGTH / 3);

				wv[0].iov_base = msg1;
				wv[1].iov_base = msg2;
				wv[2].iov_base = msg3;
				wv[0].iov_len = BUFFER_LENGTH / 3;
				wv[1].iov_len = BUFFER_LENGTH / 3;
				wv[2].iov_len = BUFFER_LENGTH / 3;
				wv_count = 3;

				if(writev(m_socket, wv, wv_count) != payload_length) {
					perror("send() sent a different number of bytes than expected");
					error++;
					break;
				}

				if((bytes_received = readv(m_socket, wv, wv_count)) <= 0) {
					perror("recv() failed or connection closed prematurely");
					error++;
					break;
				}
			}
		}
		if((!m_exit_no_close || error) && m_socket != -1) {
			close(m_socket);
		}
		return error;
	}

	int64_t get_tid() { return m_tid; }

private:
	int m_socket = -1;
	uint32_t m_server_ip_address;
	iotype m_iot;
	int64_t m_tid;
	uint32_t m_ntransactions;
	bool m_exit_no_close;
};

void runtest_ipv4m(iotype iot,
                   bool use_shutdown = false,
                   bool use_accept4 = false,
                   uint32_t ntransactions = 1,
                   bool exit_no_close = false) {
	int callnum = 0;
	tcp_server_ipv4m server(iot, use_shutdown, use_accept4, ntransactions, exit_no_close);

	uint32_t server_ip_address = get_server_address();

	struct in_addr server_in_addr;
	server_in_addr.s_addr = server_ip_address;

	char* server_address = inet_ntoa(server_in_addr);
	std::string sport;
	int state = 0;
	int ctid;
	int tid = -1;

	tcp_client_ipv4m client(server_ip_address, iot, ntransactions, exit_no_close);

	ASSERT_TRUE(server.init());
	ASSERT_TRUE(client.init());

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_tid() == server.get_tid() || evt->get_tid() == tid;
	};

	//
	// INITIALIZATION
	//
	run_callback_async_t test = [&]() {
		tid = gettid();

		// Run the server
		auto future_srv = std::async(&tcp_server_ipv4m::run, server);

		// Run the client
		if(client.run() != 0) {
			server.shutdown_server();
			future_srv.wait();
		} else {
			ctid = client.get_tid();
			ASSERT_EQ(future_srv.get(), 0);
			// We use a random call to tee to signal that we're done
			tee(-1, -1, 0, 0);
		}
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		std::string src_addr;
		std::string src_port;
		std::string dst_addr;
		std::string dst_port;

		sinsp_evt* evt = param.m_evt;
		if(evt->get_type() == PPME_SOCKET_CONNECT_X) {
			std::string tuple = evt->get_param_value_str("tuple");
			if(!parse_tuple(tuple, src_addr, src_port, dst_addr, dst_port)) {
				return;
			}

			EXPECT_NE((sinsp_fdinfo*)NULL, evt->get_fd_info());

			if(evt->get_fd_info()->m_type != SCAP_FD_IPV4_SOCK) {
				//
				// Skip non-tcp sockets. Python opens unix sockets
				// to god knows what.
				//
				return;
			}

			EXPECT_EQ(server_address, src_addr);
			if(sport == "") {
				EXPECT_NE("0", src_port);
				sport = src_port;
			} else {
				EXPECT_EQ(sport, src_port);
			}

			EXPECT_EQ(server_address, dst_addr);
			if(!exit_no_close) {
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}
			callnum++;
		} else if(evt->get_type() == PPME_SOCKET_LISTEN_E) {
			EXPECT_EQ("1", evt->get_param_value_str("backlog"));
			callnum++;
		} else if(evt->get_type() == PPME_SOCKET_LISTEN_X) {
			EXPECT_EQ("0", evt->get_param_value_str("res"));
			callnum++;
		} else if(evt->get_type() == PPME_SOCKET_ACCEPT4_6_E) {
			EXPECT_EQ("0", evt->get_param_value_str("flags"));
		} else if(evt->get_type() == PPME_SOCKET_ACCEPT_5_X ||
		          evt->get_type() == PPME_SOCKET_ACCEPT4_6_X) {
			if(!parse_tuple(evt->get_param_value_str("tuple"),
			                src_addr,
			                src_port,
			                dst_addr,
			                dst_port)) {
				return;
			}

			EXPECT_EQ(server_address, src_addr);
			if(sport == "") {
				EXPECT_NE("0", src_port);
				sport = src_port;
			} else {
				EXPECT_EQ(sport, src_port);
			}

			EXPECT_EQ(server_address, dst_addr);
			if(!exit_no_close) {
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}
			if(evt->get_type() == PPME_SOCKET_ACCEPT4_6_X) {
				EXPECT_EQ("0", evt->get_param_value_str("flags"));
			}
			callnum++;
		}

		if(callnum < 1) {
			return;
		}

		//
		// 32bit uses send() and recv(), while 64bit always uses sendto() and
		// recvfrom() and sets the address to NULL
		//
		if(evt->get_type() == PPME_SOCKET_SEND_E || evt->get_type() == PPME_SOCKET_RECV_E ||
		   evt->get_type() == PPME_SOCKET_SENDTO_E || evt->get_type() == PPME_SOCKET_RECVFROM_E) {
			if(evt->get_type() == PPME_SOCKET_RECVFROM_E) {
				if(evt->get_param_value_str("tuple") != "") {
					EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
				}
			}

			std::string tuple = evt->get_param_value_str("fd");
			tuple = tuple.substr(tuple.find(">") + 1);
			if(!parse_tuple(tuple, src_addr, src_port, dst_addr, dst_port)) {
				return;
			}

			EXPECT_EQ(server_address, src_addr);
			EXPECT_EQ(sport, src_port);

			EXPECT_EQ(server_address, dst_addr);
			if(!exit_no_close) {
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}

			callnum++;
		} else if(evt->get_type() == PPME_SOCKET_RECV_X ||
		          evt->get_type() == PPME_SOCKET_RECVFROM_X) {
			if(evt->get_type() == PPME_SOCKET_RECVFROM_X) {
				if(!parse_tuple(evt->get_param_value_str("tuple"),
				                src_addr,
				                src_port,
				                dst_addr,
				                dst_port)) {
					return;
				}
				EXPECT_EQ(server_address, src_addr);
				EXPECT_EQ(server_address, dst_addr);

				if(callnum == 7) {
					EXPECT_EQ(sport, src_port);
					if(!exit_no_close) {
						EXPECT_EQ(SERVER_PORT_STR, dst_port);
					} else {
						EXPECT_EQ(SERVER_PORT_NOCLOSE_STR, dst_port);
					}
				} else if(callnum == 9) {
					EXPECT_EQ(sport, dst_port);
					if(!exit_no_close) {
						EXPECT_EQ(SERVER_PORT_STR, src_port);
					} else {
						EXPECT_EQ(SERVER_PORT_NOCLOSE_STR, src_port);
					}
				}
			}

			EXPECT_EQ(PAYLOAD, evt->get_param_value_str("data"));

			callnum++;
		}

		if((PPME_SYSCALL_CLOSE_X == evt->get_type() || PPME_SOCKET_SHUTDOWN_X == evt->get_type()) &&
		   0 == state && evt->get_tid() == server.get_tid()) {
			if(exit_no_close) {
				FAIL();
			}

			state = 1;
		}

		if(!(use_shutdown || exit_no_close)) {
			if(evt->get_type() == PPME_GENERIC_E) {
				if(std::stoll(evt->get_param_value_str("ID", false)) == PPM_SC_TEE) {
					const auto& thread_manager = param.m_inspector->m_thread_manager;
					sinsp_threadinfo* ti =
					        thread_manager->get_thread_ref(server.get_tid(), false, true).get();
					ASSERT_NE(ti, nullptr);
					ti = thread_manager->get_thread_ref(ctid, false, true).get();
					ASSERT_NE(ti, nullptr);
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   {},
		                   131072,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   false);
	});
}

TEST_F(sys_call_test, tcp_client_server_ipv4m) {
	runtest_ipv4m(SENDRECEIVE);
}

TEST_F(sys_call_test, tcp_client_server_read_write_ipv4m) {
	runtest_ipv4m(READWRITE);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev_ipv4m) {
	runtest_ipv4m(READVWRITEV);
}

TEST_F(sys_call_test, tcp_client_server_shutdown_ipv4m) {
	runtest_ipv4m(SENDRECEIVE, true);
}

TEST_F(sys_call_test, tcp_client_server_accept4_ipv4m) {
	runtest_ipv4m(SENDRECEIVE, false, true);
}

TEST_F(sys_call_test, tcp_client_server_multiple_ipv4m) {
	runtest_ipv4m(SENDRECEIVE, false, false, 10);
}

TEST_F(sys_call_test, tcp_client_server_noclose_ipv4m) {
	runtest_ipv4m(SENDRECEIVE, false, false, 1, true);
}

TEST_F(sys_call_test, tcp_client_server_with_connection_before_capturing_starts_ipv4m) {
	tcp_server_ipv4m server(SENDRECEIVE);
	uint32_t server_ip_address = get_server_address();
	tcp_client_ipv4m client(server_ip_address, SENDRECEIVE);

	int state = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_tid() == server.get_tid() || evt->get_tid() == client.get_tid();
	};

	ASSERT_TRUE(server.init());
	ASSERT_TRUE(client.init());

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) {
		auto future_srv = std::async(&tcp_server_ipv4m::run, &server);
		auto future_client = std::async(&tcp_client_ipv4m::run, &client);
		if(future_client.get() != 0) {
			server.shutdown_server();
			future_srv.wait();
		} else {
			ASSERT_EQ(future_srv.get(), 0);
		}
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* evt = param.m_evt;
		if(PPME_SYSCALL_CLOSE_X == evt->get_type() && evt->get_tid() == server.get_tid()) {
			state = 1;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_EQ(1, state);
}
