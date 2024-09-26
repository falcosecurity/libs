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

#include <condition_variable>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

using namespace std;

#include <libsinsp/sinsp_int.h>

#define SERVER_PORT 3555
#define SERVER_PORT_STR "3555"
#define PAYLOAD "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
#define BUFFER_LENGTH (sizeof(PAYLOAD) - 1)
#define FALSE 0
#define NTRANSACTIONS 2

class udp_server {
public:
	udp_server(bool use_unix, bool use_sendmsg, bool recvmsg_twobufs, uint32_t port_offset = 0) {
		m_use_unix = use_unix;
		m_use_sendmsg = use_sendmsg;
		m_recvmsg_twobufs = recvmsg_twobufs;
		m_port = SERVER_PORT + port_offset;
		m_server_ready = false;
	}

	void run() {
		int sd = -1, rc;
		char buffer[BUFFER_LENGTH + 10];
		char buffer1[BUFFER_LENGTH - 10];
		struct sockaddr_in serveraddr;
		struct sockaddr_in clientaddr;
		socklen_t clientaddrlen = sizeof(clientaddr);
		int j;
		int domain;

		m_tid = syscall(SYS_gettid);

		if(m_use_unix) {
			domain = AF_UNIX;
		} else {
			domain = AF_INET;
		}

		do {
			sd = socket(domain, SOCK_DGRAM, 0);
			if(sd < 0) {
				perror("socket() failed");
				break;
			}

			memset(&serveraddr, 0, sizeof(serveraddr));
			serveraddr.sin_family = domain;
			serveraddr.sin_port = htons(m_port);
			serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

			rc = ::bind(sd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
			if(rc < 0) {
				perror("bind() failed");
				break;
			}

			{
				std::unique_lock<std::mutex> lock(m_mutex);
				m_server_ready = true;
				m_condition_server_ready.notify_one();
			}

			for(j = 0; j < NTRANSACTIONS; j++) {
				if(m_use_sendmsg) {
					struct msghdr msg;
					struct iovec iov[2];

					if(m_recvmsg_twobufs) {
						iov[0].iov_base = buffer1;
						iov[0].iov_len = BUFFER_LENGTH - 10;
						iov[1].iov_base = buffer;
						iov[1].iov_len = BUFFER_LENGTH - 10;

						msg.msg_name = &clientaddr;
						msg.msg_namelen = clientaddrlen;
						msg.msg_iov = iov;
						msg.msg_iovlen = 2;
						msg.msg_control = 0;
						msg.msg_controllen = 0;
						msg.msg_flags = 0;

						//
						// Receive the data
						//
						int res = recvmsg(sd, &msg, 0);
						EXPECT_EQ(res, (int)BUFFER_LENGTH);

						//
						// Set the send buffer
						//
						iov[0].iov_len = BUFFER_LENGTH - 10;
						iov[1].iov_len = 10;
					} else {
						iov[0].iov_base = buffer;
						iov[0].iov_len = BUFFER_LENGTH + 10;

						msg.msg_name = &clientaddr;
						msg.msg_namelen = clientaddrlen;
						msg.msg_iov = iov;
						msg.msg_iovlen = 1;
						msg.msg_control = 0;
						msg.msg_controllen = 0;
						msg.msg_flags = 0;

						//
						// Receive the data
						//
						int res = recvmsg(sd, &msg, 0);
						EXPECT_EQ(res, (int)BUFFER_LENGTH);

						//
						// Set the send buffer
						//
						iov[0].iov_len = BUFFER_LENGTH;
					}

					//
					// Echo the data back to the client
					//
					if(sendmsg(sd, &msg, 0) == -1) {
						perror("sendmsg() failed");
						break;
					}
				} else {
					//
					// Receive the data
					//
					rc = recvfrom(sd,
					              buffer,
					              sizeof(buffer),
					              0,
					              (struct sockaddr*)&clientaddr,
					              &clientaddrlen);
					if(rc < 0) {
						perror("recvfrom() failed");
						break;
					}

					//
					// Echo the data back to the client
					//
					rc = sendto(sd,
					            buffer,
					            sizeof(buffer),
					            0,
					            (struct sockaddr*)&clientaddr,
					            sizeof(clientaddr));
					if(rc < 0) {
						FAIL();
						perror("sendto() failed");
						break;
					}
				}
			}
		} while(FALSE);

		if(sd != -1)
			close(sd);
	}

	void wait_for_server_ready() {
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			m_condition_server_ready.wait(lock, [this]() { return m_server_ready; });
			m_server_ready = false;
		}
	}

	int64_t get_tid() { return m_tid; }

private:
	std::mutex m_mutex;
	std::condition_variable m_condition_server_ready;
	bool m_server_ready;
	int64_t m_tid;
	bool m_use_unix;
	bool m_use_sendmsg;
	bool m_recvmsg_twobufs;
	uint16_t m_port;
};

class udp_client {
public:
	udp_client(uint32_t server_ip_address,
	           bool use_connect,
	           uint16_t base_port = SERVER_PORT,
	           uint32_t num_servers = 1):
	        m_use_sendmsg(false),
	        m_recv(true),
	        m_payload(PAYLOAD),
	        m_ignore_errors(false),
	        m_n_transactions(NTRANSACTIONS) {
		m_use_unix = false;
		m_server_ip_address = server_ip_address;
		m_use_connect = use_connect;
		for(uint32_t idx = 0; idx < num_servers; idx++) {
			m_server_ports.push_back(base_port + idx);
		}
	}

	void run() {
		int sd;
		int domain;

		if(m_use_unix) {
			domain = AF_UNIX;
		} else {
			domain = AF_INET;
		}

		sd = socket(domain, SOCK_DGRAM, 0);
		if(sd < 0) {
			FAIL();
		}

		for(auto port : m_server_ports) {
			run_using_port(sd, domain, port);
		}

		if(sd != -1) {
			close(sd);
		}
	}

	void run_using_port(int sd, int domain, uint16_t port) {
		int rc;
		int j;
		struct sockaddr_in serveraddr;
		socklen_t serveraddrlen = sizeof(serveraddr);

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family = domain;
		serveraddr.sin_port = htons(port);
		serveraddr.sin_addr.s_addr = m_server_ip_address;

		if(m_use_connect) {
			if(connect(sd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0 &&
			   !m_ignore_errors) {
				close(sd);
				FAIL() << "connect() failed";
			}
		}

		for(j = 0; j < m_n_transactions; j++) {
			if(!m_use_sendmsg) {
				if(m_use_connect) {
					rc = sendto(sd, m_payload.data(), m_payload.size(), 0, NULL, 0);
				} else {
					rc = sendto(sd,
					            m_payload.data(),
					            m_payload.size(),
					            0,
					            (struct sockaddr*)&serveraddr,
					            sizeof(serveraddr));
				}
			} else {
				struct msghdr msg = {0};
				if(m_use_connect) {
					msg.msg_name = NULL;
				} else {
					msg.msg_name = (void*)&serveraddr;
					msg.msg_namelen = sizeof(serveraddr);
				}
				struct iovec iov;
				iov.iov_base = (void*)m_payload.data();
				iov.iov_len = m_payload.size();
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				rc = sendmsg(sd, &msg, MSG_DONTWAIT);
			}
			if(rc < 0 && !m_ignore_errors) {
				close(sd);
				FAIL();
			}

			//
			// Use the recvfrom() function to receive the data back from the
			// server.
			//
			if(m_recv) {
				char* buffer = (char*)malloc(m_payload.size());
				rc = recvfrom(sd,
				              buffer,
				              m_payload.size(),
				              0,
				              (struct sockaddr*)&serveraddr,
				              &serveraddrlen);
				free(buffer);
				if(rc < 0 && !m_ignore_errors) {
					close(sd);
					FAIL();
				}
			}
		}
	}

	bool m_use_sendmsg;
	bool m_recv;
	std::string m_payload;
	bool m_use_connect;
	bool m_ignore_errors;
	int m_n_transactions;

private:
	bool m_use_unix;
	uint32_t m_server_ip_address;
	std::vector<uint16_t> m_server_ports;
};

class udp_servers_and_client {
public:
	udp_servers_and_client(bool use_unix,
	                       bool use_sendmsg,
	                       bool recvmsg_twobufs,
	                       bool use_connect,
	                       uint32_t num_servers) {
		m_server_ip_address = get_server_address();
		struct in_addr server_in_addr;
		server_in_addr.s_addr = m_server_ip_address;
		m_server_address = inet_ntoa(server_in_addr);
		m_use_connect = use_connect;

		for(uint32_t idx = 0; idx < num_servers; idx++) {
			m_server_ports.insert(SERVER_PORT + idx);
			m_servers.emplace_back(
			        std::make_shared<udp_server>(use_unix, use_sendmsg, recvmsg_twobufs, idx));
		}
	}

	uint32_t server_ip_address() { return m_server_ip_address; }

	std::string& server_address() { return m_server_address; }

	bool is_server_tid(int64_t tid) {
		for(auto& srv : m_servers) {
			if(tid == srv->get_tid()) {
				return true;
			}
		}

		return false;
	}

	std::vector<std::shared_ptr<udp_server>>& get_servers() { return m_servers; }

	bool is_server_port(std::string& portstr) {
		uint16_t port = std::stoi(portstr);

		return (port >= SERVER_PORT && port < SERVER_PORT + m_servers.size());
	}

	bool filter(sinsp_evt* evt) { return is_server_tid(evt->get_tid()); }

	std::string server_port_yaml() {
		std::stringstream out;
		for(auto port : m_server_ports) {
			out << "  - " << port << "\n";
		}
		return out.str();
	}

	void start() {
		for(uint32_t idx = 0; idx < m_servers.size(); idx++) {
			m_threads.emplace_back(std::thread(&udp_server::run, m_servers[idx]));
			m_servers[idx]->wait_for_server_ready();
		}

		udp_client client(m_server_ip_address, m_use_connect, SERVER_PORT, m_servers.size());
		client.run();

		for(auto& thread : m_threads) {
			thread.join();
		}
	}

private:
	uint32_t m_server_ip_address;
	std::string m_server_address;
	std::vector<std::thread> m_threads;
	std::vector<std::shared_ptr<udp_server>> m_servers;
	std::set<uint16_t> m_server_ports;
	bool m_use_connect;
};

inline void parse_tuple(const std::string& tuple,
                        std::string& src_addr,
                        std::string& src_port,
                        std::string& dst_addr,
                        std::string& dst_port) {
	std::string token;
	std::stringstream ss(tuple);
	std::vector<std::string> tst;
	while(std::getline(ss, token, '>')) {
		tst.push_back(token);
	}

	std::string srcstr = tst[0].substr(0, tst[0].size() - 1);
	std::string dststr = tst[1];

	ss.clear();
	ss.str(srcstr);
	std::vector<std::string> sst;
	while(std::getline(ss, token, ':')) {
		sst.push_back(token);
	}

	EXPECT_EQ(2, (int)sst.size());
	src_addr = sst[0];
	src_port = sst[1];

	ss.clear();
	ss.str(dststr);
	std::vector<std::string> dst;
	while(std::getline(ss, token, ':')) {
		dst.push_back(token);
	}
	EXPECT_EQ(2, (int)dst.size());
	dst_addr = dst[0];
	dst_port = dst[1];
}

TEST_F(sys_call_test, udp_client_server) {
	int32_t state = 0;
	bool use_unix = false, use_sendmsg = false, recvmsg_twobufs = false, use_connect = false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);
	int64_t fd_server_socket = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return udps.filter(evt) || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) { udps.start(); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string src_addr;
		std::string src_port;
		std::string dst_addr;
		std::string dst_port;

		if(type == PPME_SOCKET_RECVFROM_E) {
			memcpy(&fd_server_socket, e->get_param(0)->m_val, sizeof(fd_server_socket));
		}
		switch(state) {
		case 0:
			EXPECT_NE(PPME_SOCKET_SENDTO_X, type);
			EXPECT_NE(PPME_SOCKET_RECVFROM_X, type);

			if(type == PPME_SOCKET_SENDTO_E) {
				parse_tuple(e->get_param_value_str("tuple"),
				            src_addr,
				            src_port,
				            dst_addr,
				            dst_port);
				EXPECT_EQ("0.0.0.0", src_addr);

				EXPECT_EQ(udps.server_address(), dst_addr);
				EXPECT_TRUE(udps.is_server_port(dst_port));

				state++;
			}
			break;
		case 1:
			if(type == PPME_SOCKET_RECVFROM_X) {
				parse_tuple(e->get_param_value_str("tuple"),
				            src_addr,
				            src_port,
				            dst_addr,
				            dst_port);

				EXPECT_EQ(udps.server_address(), src_addr);
				EXPECT_NE("0", src_port);
				EXPECT_EQ("0.0.0.0", dst_addr);
				EXPECT_TRUE(udps.is_server_port(dst_port));

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo* fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				ASSERT_TRUE(fdinfo);
				EXPECT_EQ(udps.server_ip_address(), fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

				state++;
			}
			break;
		case 2:
			EXPECT_NE(PPME_SOCKET_SENDTO_X, type);
			EXPECT_NE(PPME_SOCKET_RECVFROM_X, type);

			if(type == PPME_SOCKET_SENDTO_E) {
				parse_tuple(e->get_param_value_str("tuple"),
				            src_addr,
				            src_port,
				            dst_addr,
				            dst_port);

				EXPECT_EQ("0.0.0.0", src_addr);
				EXPECT_TRUE(udps.is_server_port(src_port));
				EXPECT_EQ(udps.server_address(), dst_addr);
				EXPECT_NE("0", dst_port);

				state++;
			}
			break;
		case 3:
			if(type == PPME_SOCKET_RECVFROM_X) {
				parse_tuple(e->get_param_value_str("tuple"),
				            src_addr,
				            src_port,
				            dst_addr,
				            dst_port);

				EXPECT_EQ(udps.server_address(), src_addr);
				EXPECT_TRUE(udps.is_server_port(src_port));

				EXPECT_EQ("0.0.0.0", dst_addr);
				EXPECT_NE("0", dst_port);

				EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
				sinsp_fdinfo* fdinfo = e->get_thread_info(false)->get_fd(fd_server_socket);
				ASSERT_TRUE(fdinfo);
				EXPECT_EQ(udps.server_ip_address(), fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);

				state = 4;
			}
			break;
		case 4:
			break;
		default:
			FAIL();
			break;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, udp_client_server_with_connect_by_client) {
	bool use_unix = false, use_sendmsg = false, recvmsg_twobufs = false, use_connect = true;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);
	std::string src_addr;
	std::string src_port;
	std::string dst_addr;
	std::string dst_port;

	int callnum = 0;
	std::string client_port;
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return udps.filter(evt) || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) { udps.start(); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(PPME_SOCKET_CONNECT_X == type) {
			parse_tuple(e->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ(udps.server_address(), src_addr);

			EXPECT_EQ(udps.server_address(), dst_addr);
			EXPECT_TRUE(udps.is_server_port(dst_port));

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_EQ(1, callnum);
}

TEST_F(sys_call_test, udp_client_server_sendmsg) {
	bool use_unix = false, use_sendmsg = true, recvmsg_twobufs = false, use_connect = false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return udps.filter(evt) || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) { udps.start(); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string src_addr;
		std::string src_port;
		std::string dst_addr;
		std::string dst_port;

		if(type == PPME_SOCKET_RECVMSG_X) {
			std::cout << e->get_param_value_str("tuple") << std::endl;
			parse_tuple(e->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ(udps.server_address(), src_addr);
			EXPECT_NE("0", src_port);
			EXPECT_EQ("0.0.0.0", dst_addr);
			EXPECT_TRUE(udps.is_server_port(dst_port));

			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

			EXPECT_EQ(udps.server_ip_address(),
			          e->get_fd_info()->m_sockinfo.m_ipv4info.m_fields.m_sip);
		} else if(type == PPME_SOCKET_SENDMSG_E) {
			parse_tuple(e->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ("0.0.0.0", src_addr);
			EXPECT_TRUE(udps.is_server_port(src_port));
			EXPECT_EQ(udps.server_address(), dst_addr);
			EXPECT_NE("0", dst_port);

			EXPECT_EQ((int)BUFFER_LENGTH, std::stoi(e->get_param_value_str("size")));
		} else if(type == PPME_SOCKET_SENDMSG_X) {
			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, udp_client_server_sendmsg_2buf) {
	bool use_unix = false, use_sendmsg = true, recvmsg_twobufs = true, use_connect = false;
	uint32_t num_servers = 1;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return udps.filter(evt) || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) { udps.start(); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string src_addr;
		std::string src_port;
		std::string dst_addr;
		std::string dst_port;

		if(type == PPME_SOCKET_RECVMSG_X) {
			parse_tuple(e->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ(udps.server_address(), src_addr);
			EXPECT_NE("0", src_port);
			EXPECT_EQ("0.0.0.0", dst_addr);
			EXPECT_TRUE(udps.is_server_port(dst_port));

			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));

			EXPECT_EQ(udps.server_ip_address(),
			          e->get_fd_info()->m_sockinfo.m_ipv4info.m_fields.m_sip);
		} else if(type == PPME_SOCKET_SENDMSG_E) {
			parse_tuple(e->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ("0.0.0.0", src_addr);
			EXPECT_TRUE(udps.is_server_port(src_port));

			EXPECT_EQ(udps.server_address(), dst_addr);
			EXPECT_NE("0", dst_port);
			EXPECT_EQ((int)BUFFER_LENGTH, std::stoi(e->get_param_value_str("size")));
		} else if(type == PPME_SOCKET_SENDMSG_X) {
			EXPECT_EQ(PAYLOAD, e->get_param_value_str("data"));
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

static void run_fd_name_changed_test(bool use_sendmsg,
                                     bool recvmsg_twobufs,
                                     bool use_connect,
                                     event_filter_t m_tid_filter,
                                     uint32_t expected_name_changed_evts) {
	bool use_unix = false;
	uint32_t num_servers = 2;
	udp_servers_and_client udps(use_unix, use_sendmsg, recvmsg_twobufs, use_connect, num_servers);

	unique_ptr<sinsp_filter> fd_name_changed;

	uint32_t num_name_changed_evts = 0;

	// INIT FILTER
	before_open_t before_open = [&](sinsp* inspector) {
		sinsp_filter_compiler compiler(inspector, "fd.name_changed=true");
		fd_name_changed = std::move(compiler.compile());
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return udps.filter(evt) || m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) { udps.start(); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		if(fd_name_changed->run(e)) {
			num_name_changed_evts++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });

	ASSERT_EQ(num_name_changed_evts, expected_name_changed_evts);
}

TEST_F(sys_call_test, udp_client_server_fd_name_changed) {
	bool use_sendmsg = false, recvmsg_twobufs = false, use_connect = false;

	// This test only needs to count events. We want to
	// see 7 events, representing the following:
	//  - The servers bind()ing their sockets to their server ports.
	//  - the udp client sending to the first server.
	//  - the first udp server receiving from the udp client
	//  - the udp client receiving the echoed response from the first udp server.
	//    This results in an event, even though this fd has already
	//    been used between the server and client, because this
	//    recvfrom sets the client side port as a result of
	//    the recvfrom().
	//  - the udp client sending to the second server
	//  - the second udp server receiving from the udp client
	//
	// Events that do *not* trigger name_changed are:
	//  - the first/second udp server sending the echoed response to the udp client. This is because
	//  it's using
	//    the same client/server address + port as when it received the packet from the udp client.
	//  - the udp client receiving the second echo back from the second server. This is because
	//    the client side port was already set from the communication with the first server.

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, udp_client_server_connect_fd_name_changed) {
	bool use_sendmsg = false, recvmsg_twobufs = false, use_connect = true;

	// When the client uses connect, there is one fewer name
	// changed event, as there is no name change when the client
	// receives the echoed response from the server.

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 6);
}

TEST_F(sys_call_test, udp_client_server_sendmsg_fd_name_changed) {
	bool use_sendmsg = true, recvmsg_twobufs = false, use_connect = false;

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, udp_client_server_multiple_connect_name_changed) {
	unique_ptr<sinsp_filter> fd_name_changed;
	uint32_t num_name_changed_evts = 0;

	// INIT FILTER
	before_open_t before_open = [&](sinsp* inspector) {
		sinsp_filter_compiler compiler(inspector, "fd.name_changed=true");
		fd_name_changed = std::move(compiler.compile());
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) {
		int sd;

		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if(sd < 0) {
			FAIL();
		}

		std::list<uint16_t> ports = {8172, 8193, 8193, 8172, 8171};

		for(auto& port : ports) {
			struct sockaddr_in serveraddr;

			memset(&serveraddr, 0, sizeof(serveraddr));
			serveraddr.sin_family = AF_INET;
			serveraddr.sin_port = htons(port);
			serveraddr.sin_addr.s_addr = get_server_address();

			if(connect(sd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
				close(sd);
				FAIL() << "connect() failed";
			}
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		if(fd_name_changed->run(e)) {
			num_name_changed_evts++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });

	// Every connect should result in a name changed event other than the duplicate port.
	ASSERT_EQ(num_name_changed_evts, 4u);
}

TEST_F(sys_call_test, udp_client_server_sendmsg_2buf_fd_name_changed) {
	bool use_sendmsg = true, recvmsg_twobufs = true, use_connect = false;

	run_fd_name_changed_test(use_sendmsg, recvmsg_twobufs, use_connect, m_tid_filter, 7);
}

TEST_F(sys_call_test, statsd_client_snaplen) {
	// Test if the driver correctly increase snaplen for statsd traffic
	std::string payload =
	        "soluta.necessitatibus.voluptatem.consequuntur.dignissimos.repudiandae.nostrum.lorem."
	        "ipsum:"
	        "18|c";

	before_open_t setup = [&](sinsp* inspector) { inspector->dynamic_snaplen(true); };

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return m_tid_filter(evt) && (evt->get_type() == PPME_SOCKET_SENDMSG_X ||
		                             evt->get_type() == PPME_SOCKET_SENDTO_X);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) {
		// sendto with addr
		udp_client client(0x0100007F, false, 8125);
		client.m_payload = payload;
		client.m_ignore_errors = true;
		client.m_recv = false;
		client.m_n_transactions = 1;
		client.run();

		// sendto without addr (connect)
		client.m_use_connect = true;
		client.run();

		// sendmsg with addr
		client.m_use_connect = false;
		client.m_use_sendmsg = true;
		client.run();

		// sendmsg without addr
		client.m_use_connect = true;
		client.run();
	};

	//
	// OUTPUT VALDATION
	//
	int n = 0;
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		EXPECT_EQ(payload, e->get_param_value_str("data"))
		        << "Failure on " << e->get_name() << " n=" << n;
		n++;
	};

	before_close_t cleanup = [&](sinsp* inspector) { inspector->dynamic_snaplen(false); };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
	EXPECT_EQ(4, n);
}

TEST_F(sys_call_test, statsd_client_no_snaplen) {
	// Test if the driver correctly increase snaplen for statsd traffic
	std::string payload =
	        "soluta.necessitatibus.voluptatem.consequuntur.dignissimos.repudiandae.nostrum.lorem."
	        "ipsum:"
	        "18|c";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return m_tid_filter(evt) && (evt->get_type() == PPME_SOCKET_SENDMSG_X ||
		                             evt->get_type() == PPME_SOCKET_SENDTO_X);
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](sinsp* inspector) {
		// sendto with addr
		// Different port
		udp_client client(0x0100007F, false, 8126);
		client.m_payload = payload;
		client.m_ignore_errors = true;
		client.m_recv = false;
		client.m_n_transactions = 1;
		client.run();

		// sendto without addr (connect)
		client.m_use_connect = true;
		client.run();

		// sendmsg with addr
		client.m_use_connect = false;
		client.m_use_sendmsg = true;
		client.run();

		// sendmsg without addr
		client.m_use_connect = true;
		client.run();
	};

	//
	// OUTPUT VALDATION
	//
	int n = 0;
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		++n;
		EXPECT_EQ(payload.substr(0, 80), e->get_param_value_str("data"))
		        << "Failure on " << e->get_name() << " n=" << n;
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, n);
}
