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

#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>
#include "test_utils.h"
#include <arpa/inet.h>
#include <netinet/in.h>

#define DEFAULT_IPV4_CLIENT_STRING "172.40.111.222"
#define DEFAULT_IPV6_CLIENT_STRING "::1"
#define DEFAULT_CLIENT_PORT_STRING "54321"
#define DEFAULT_CLIENT_PORT 54321

#define DEFAULT_IPV4_SERVER_STRING "142.251.111.147"
#define DEFAULT_IPV6_SERVER_STRING "2001:4860:4860::8888"
#define DEFAULT_SERVER_PORT_STRING "443"
#define DEFAULT_SERVER_PORT 443

#define DEFAULT_IPV4_FDNAME "172.40.111.222:54321->142.251.111.147:443"
#define DEFAULT_IPV6_FDNAME "::1:54321->2001:4860:4860::8888:443"

#define DEFAULT_IP_STRING_SIZE 100

int64_t return_value = 0;

/*
 * For all network tests we can use the prefix `net` for tests
 */
TEST_F(sinsp_with_test_input, net_socket)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;

	int64_t client_fd = 9;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM,  (uint32_t) 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_EQ(fdinfo->get_l4proto(), SCAP_L4_NA); /// todo: probably this is not what we want
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	ASSERT_TRUE(fdinfo->is_tcp_socket());
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_pending());
	ASSERT_FALSE(fdinfo->is_socket_failed());
	ASSERT_FALSE(fdinfo->is_socket_connected());

	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "<NA>"); /// todo: probably this is not what we want
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	/* When the fd role is `none` all these fields return NULL */
	ASSERT_FALSE(field_has_value(evt, "fd.sip"));
	ASSERT_FALSE(field_has_value(evt, "fd.cip"));
	ASSERT_FALSE(field_has_value(evt, "fd.rip"));
	ASSERT_FALSE(field_has_value(evt, "fd.lip"));
	ASSERT_FALSE(field_has_value(evt, "fd.cport"));
	ASSERT_FALSE(field_has_value(evt, "fd.sport"));
	ASSERT_FALSE(field_has_value(evt, "fd.lport"));
	ASSERT_FALSE(field_has_value(evt, "fd.rport"));
}

TEST_F(sinsp_with_test_input, net_ipv4_connect)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	sinsp_threadinfo* tinfo = NULL;
	char ipv4_string[DEFAULT_IP_STRING_SIZE];
	int64_t client_fd = 7;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
	sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	/* See the `reset` logic for enter events with `EF_USES_FD` flag */
	tinfo = evt->get_thread_info(false);
	ASSERT_NE(tinfo, nullptr);
	ASSERT_EQ(tinfo->m_lastevent_fd, client_fd);
	ASSERT_EQ(tinfo->m_lastevent_ts, evt->get_ts());
	ASSERT_EQ(tinfo->m_latency, 0);

	/* Here we should recover the fdinfo from the thread info since the socket call has already added the fdinfo into the thread.
	 * See `reset` logic, the fdinfo is recovered from the `client_fd` (first parameter).
	 */
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_TRUE(fdinfo->is_ipv4_socket()); /* in `parse_connect_enter` we set `SCAP_FD_IPV4_SOCK` as type */
	ASSERT_TRUE(fdinfo->is_role_none());   /* The connect enter event is not able to set a role */
	ASSERT_FALSE(fdinfo->is_role_client());
	ASSERT_FALSE(fdinfo->is_role_server());
	ASSERT_FALSE(fdinfo->is_socket_connected());
	ASSERT_FALSE(fdinfo->is_socket_failed());
	ASSERT_FALSE(fdinfo->is_socket_pending());

	/* Check that ip and port are saved from the server sockaddr in the fdinfo */
	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, DEFAULT_SERVER_PORT);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");
	/* Since the role of the fd is none, all these fields are null. The fdinfo state is updated but we cannot use these info in the filterchecks */
	ASSERT_FALSE(field_has_value(evt, "fd.sip"));

	/* If the exit event is immediately consecutive we can obtain some info otherwise there is the risk we cannot update the fd */
	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	ASSERT_TRUE(fdinfo->is_socket_connected()); /* in the parse exit we set the socket as connected */
	ASSERT_TRUE(fdinfo->is_role_client());	    /* The connect exit set the client role */

	/* Check that ip and port are saved from the server socktuple */
	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_CLIENT_STRING);
	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, DEFAULT_SERVER_PORT);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport, DEFAULT_CLIENT_PORT);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV4_FDNAME);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV4_SERVER_STRING);

	/* The concept of remote ip is quite strange, we check if the client address is one of our interfaces, if yes
	 * the remote ip will be the server otherwise it will be the client! In this case, the client IP is completely random
	 * so it will be considered as remote, while the server ip will be local!
	 */
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), DEFAULT_SERVER_PORT_STRING);
}

TEST_F(sinsp_with_test_input, net_ipv4_connect_with_intermediate_event)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	int64_t client_fd = 8;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);

	sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	/* This should never happen but could cause strange outcomes */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SENDTO_E, 3, client_fd, (uint32_t)102, scap_const_sized_buffer{socktuple.data(), socktuple.size()});
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	/* We are able to recover the fdinfo in the connect exit event even when interleaved */
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);

	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "172.40.111.222:54321->142.251.111.147:443");
}

TEST_F(sinsp_with_test_input, net_ipv6_multiple_connects)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t client_fd = 9;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET6, (uint32_t) SOCK_DGRAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in6 client = test_utils::fill_sockaddr_in6(DEFAULT_CLIENT_PORT, DEFAULT_IPV6_CLIENT_STRING);

	sockaddr_in6 server1 = test_utils::fill_sockaddr_in6(DEFAULT_SERVER_PORT, DEFAULT_IPV6_SERVER_STRING);

	std::vector<uint8_t> server1_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server1));

	/* The connect enter event populates the destination ip and the destination port thanks to the `server_sockaddr` */
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server1_sockaddr.data(), server1_sockaddr.size()});

	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server1));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV6_FDNAME);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV6_SERVER_STRING);

	/* The concept of remote ip is quite strange, we check if the client address is one of our interfaces, if yes
	 * the remote ip will be the server otherwise it will be the client! In this case, the client IP is completely random
	 * so it will be considered as remote, while the server ip will be local!
	 */
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV6_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV6_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), DEFAULT_IPV6_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), DEFAULT_SERVER_PORT_STRING);

	/* Connection with the second server */
	int port_server2 = 8;
	std::string ipv6_server2 = "2001:4860:4860::8888";
	std::string port_server2_string = "8";
	sockaddr_in6 server2 = test_utils::fill_sockaddr_in6(port_server2, ipv6_server2.c_str());
	std::vector<uint8_t> server2_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server2));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server2_sockaddr.data(), server2_sockaddr.size()});
	/* check that upon entry to the new connect the fd name is the same as during the last connection */
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV6_FDNAME);
	/* server ip and port are updated with the new connect enter event */
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), ipv6_server2);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), ipv6_server2);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), port_server2_string);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), port_server2_string);

	socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server2));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "true");
	std::string new_fd_name = std::string(DEFAULT_IPV6_CLIENT_STRING) + ":" + std::string(DEFAULT_CLIENT_PORT_STRING) + "->" + ipv6_server2 + ":" + port_server2_string;
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), new_fd_name);

	scap_const_sized_buffer null_buf = scap_const_sized_buffer{nullptr, 0};
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SENDTO_E, 3, client_fd, (uint32_t) 6, null_buf);
	/* the tuple of `sendto` is empty so we won't update anything */
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), new_fd_name);
}

/* test a basic server connection with ipv4 */
TEST_F(sinsp_with_test_input, net_bind_listen_accept_ipv4)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	char ipv4_string[DEFAULT_IP_STRING_SIZE];

	int64_t server_fd = 3;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, server_fd);

	/* We have no parsers for bind enter event */
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_E, 1, server_fd);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");

	sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);
	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_X, 2, return_value, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_FALSE(fdinfo->is_ipv4_socket());
	ASSERT_FALSE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_role_client());
	ASSERT_TRUE(fdinfo->is_role_server());
	ASSERT_FALSE(fdinfo->is_socket_connected());
	ASSERT_FALSE(fdinfo->is_socket_failed());
	ASSERT_FALSE(fdinfo->is_socket_pending());

	/* Check that ip and port are saved from the server sockaddr in the fdinfo */
	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port, DEFAULT_SERVER_PORT);

	/* The fdname is just the server ip + server port */
	std::string fdname = std::string(DEFAULT_IPV4_SERVER_STRING) + ":" + std::string(DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_FALSE(field_has_value(evt, "fd.cip")); /* we are not able to retrieve the client ip, the fdinfo type is SCAP_FD_IPV4_SERVSOCK */
	ASSERT_FALSE(field_has_value(evt, "fd.rip")); /* we are not able to retrieve remote ip, the fdinfo type is SCAP_FD_IPV4_SERVSOCK */
	ASSERT_FALSE(field_has_value(evt, "fd.lip")); /* we are not able to retrieve local ip, the fdinfo type is SCAP_FD_IPV4_SERVSOCK */
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_FALSE(field_has_value(evt, "fd.cport"));
	ASSERT_FALSE(field_has_value(evt, "fd.rport"));
	ASSERT_FALSE(field_has_value(evt, "fd.lport"));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_E, 2, server_fd, (uint32_t) 5);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_X, 1, return_value);

	sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);

	std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));

	int64_t new_connected_fd = 6;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, new_connected_fd, scap_const_sized_buffer{st.data(), st.size()}, (uint8_t) 0, (uint32_t) 0, (uint32_t) 5);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV4_FDNAME);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "tcp");
}

/* test a basic server connection with ipv6 */
TEST_F(sinsp_with_test_input, net_bind_listen_accept_ipv6)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	int64_t server_fd = 3;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET6, (uint32_t) SOCK_STREAM, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, server_fd);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_E, 1, server_fd);

	sockaddr_in6 server = test_utils::fill_sockaddr_in6(DEFAULT_SERVER_PORT, DEFAULT_IPV6_SERVER_STRING);
	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_X, 2, return_value, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
	std::string fdname = std::string(DEFAULT_IPV6_SERVER_STRING) + ":" + std::string(DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "true");

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_E, 2, server_fd, (uint32_t) 5);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_X, 1, return_value);

	sockaddr_in6 client = test_utils::fill_sockaddr_in6(DEFAULT_CLIENT_PORT, DEFAULT_IPV6_CLIENT_STRING);

	std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));

	int64_t new_connected_fd = 6;
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, new_connected_fd, scap_const_sized_buffer{st.data(), st.size()}, (uint8_t) 0, (uint32_t) 0, (uint32_t) 5);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV6_FDNAME);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV6_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV6_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV6_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), DEFAULT_IPV6_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "tcp");
}

TEST_F(sinsp_with_test_input, net_connect_exit_event_fails)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	char ipv4_string[DEFAULT_IP_STRING_SIZE];
	int64_t client_fd = 7;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);

	sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

	/* First connection to populate the fdinfo */

	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()}, client_fd);

	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()});

	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->m_name.c_str(), DEFAULT_IPV4_FDNAME);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), DEFAULT_IPV4_FDNAME);

	/* Second connection with another server but in this case, the connect exit event fails */
	int port_server2 = 25632;
	std::string ipv4_server2 = "152.40.111.222";
	std::string port_server2_string = "25632";
	sockaddr_in server2 = test_utils::fill_sockaddr_in(port_server2, ipv4_server2.c_str());

	server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server2));
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server2));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, (int64_t)-2, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	/* Filterchecks will get an updated fdname since the extraction happens directly on the params, while the fdinfo fdname is not updated.
	 * Ip and port of the new server are updated by the PPME_SOCKET_CONNECT_E event so both filterchecks and internal state are aligned
	 */

	std::string fdname = std::string(DEFAULT_IPV4_CLIENT_STRING) + ":" + std::string(DEFAULT_CLIENT_PORT_STRING) + "->" + ipv4_server2 + ":" + port_server2_string;
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), ipv4_server2);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), ipv4_server2);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), port_server2_string);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), port_server2_string);

	/* The parser is not able to obtain an updated fdname because the syscall fails and the parser flow is truncated */
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->m_name.c_str(), DEFAULT_IPV4_FDNAME);

	/* There are updated by the enter event */
	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, ipv4_server2.c_str());

	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_CLIENT_STRING);

	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, port_server2);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport, DEFAULT_CLIENT_PORT);
}

TEST_F(sinsp_with_test_input, net_connect_enter_event_is_empty)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	char ipv4_string[DEFAULT_IP_STRING_SIZE];
	int64_t client_fd = 7;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_DGRAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);

	sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

	/* First connection to populate the fdinfo */

	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	/* Second connection with an empty sockaddr in the PPME_SOCKET_CONNECT_E event, new client and new server */

	int port_client2 = 12;
	std::string ipv4_client2 = "80.9.11.45";
	std::string port_client2_string = "12";
	sockaddr_in client2 = test_utils::fill_sockaddr_in(port_client2, ipv4_client2.c_str());

	int port_server2 = 25632;
	std::string ipv4_server2 = "152.40.111.222";
	std::string port_server2_string = "25632";
	sockaddr_in server2 = test_utils::fill_sockaddr_in(port_server2, ipv4_server2.c_str());

	scap_const_sized_buffer null_buf = scap_const_sized_buffer{nullptr, 0};
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, null_buf);

	socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client2), reinterpret_cast<sockaddr*>(&server2));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, (int64_t)-2, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	/* Only filterchecks will see the new tuple in the fdname all the rest is not updated */
	std::string fdname = ipv4_client2 + ":" + port_client2_string + "->" + ipv4_server2 + ":" + port_server2_string;
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), DEFAULT_IPV4_CLIENT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), DEFAULT_IPV4_SERVER_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), DEFAULT_SERVER_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), DEFAULT_CLIENT_PORT_STRING);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), DEFAULT_SERVER_PORT_STRING);

	/* The parser is not able to obtain an updated fdname because the syscall fails and the parser flow is truncated */
	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->m_name.c_str(), DEFAULT_IPV4_FDNAME);

	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_SERVER_STRING);

	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, DEFAULT_IPV4_CLIENT_STRING);

	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, DEFAULT_SERVER_PORT);
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport, DEFAULT_CLIENT_PORT);
}

TEST_F(sinsp_with_test_input, net_connect_enter_event_is_missing)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	char ipv4_string[DEFAULT_IP_STRING_SIZE];
	int64_t client_fd = 7;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_DGRAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	int port_client = 12;
	std::string ipv4_client = "80.9.11.45";
	std::string port_client_string = "12";
	sockaddr_in client = test_utils::fill_sockaddr_in(port_client, ipv4_client.c_str());

	int port_server = 25632;
	std::string ipv4_server = "152.40.111.222";
	std::string port_server_string = "25632";
	sockaddr_in server = test_utils::fill_sockaddr_in(port_server, ipv4_server.c_str());

	/* We dropped connect enter! */

	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	/* Check that everything is updated anyway, even if we lost connect enter */
	std::string fdname = ipv4_client + ":" + port_client_string + "->" + ipv4_server + ":" + port_server_string;
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), ipv4_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), ipv4_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), ipv4_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), ipv4_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), ipv4_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), port_server_string);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), port_client_string);
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), port_client_string);
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), port_server_string);

	fdinfo = evt->get_fd_info();
	ASSERT_NE(fdinfo, nullptr);
	ASSERT_STREQ(fdinfo->m_name.c_str(), fdname.c_str());

	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, ipv4_server.c_str());

	inet_ntop(AF_INET, (uint8_t*)&(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip), ipv4_string, 100);
	ASSERT_STREQ(ipv4_string, ipv4_client.c_str());

	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, std::stoi(port_server_string));
	ASSERT_EQ(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport, std::stoi(port_client_string));
}

/*
 * Test that old connect exit event without the third `fd` argument
 * were not able to load fd related data if connect enter was dropped.
 */
TEST_F(sinsp_with_test_input, net_connect_enter_event_is_missing_wo_fd_param_exit)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	sinsp_fdinfo* fdinfo = NULL;
	int64_t client_fd = 7;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_DGRAM, (uint32_t) 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	int port_client = 12;
	std::string ipv4_client = "80.9.11.45";
	std::string port_client_string = "12";
	sockaddr_in client = test_utils::fill_sockaddr_in(port_client, ipv4_client.c_str());

	int port_server = 25632;
	std::string ipv4_server = "152.40.111.222";
	std::string port_server_string = "25632";
	sockaddr_in server = test_utils::fill_sockaddr_in(port_server, ipv4_server.c_str());

	/* We dropped connect enter! */

	/* We read an old scap file with a connect exit event with just 2 params (no fd!) */
	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 2, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()});

	/* Check that we are not able to load any info */
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "");
	ASSERT_FALSE(field_has_value(evt, "fd.sip"));
	ASSERT_FALSE(field_has_value(evt, "fd.cip"));
	ASSERT_FALSE(field_has_value(evt, "fd.rip"));
	ASSERT_FALSE(field_has_value(evt, "fd.lip"));
	ASSERT_FALSE(field_has_value(evt, "fd.cport"));
	ASSERT_FALSE(field_has_value(evt, "fd.sport"));
	ASSERT_FALSE(field_has_value(evt, "fd.lport"));
	ASSERT_FALSE(field_has_value(evt, "fd.rport"));

	/* The parser is not able to obtain an updated fdname because the syscall fails and the parser flow is truncated */
	fdinfo = evt->get_fd_info();
	ASSERT_EQ(fdinfo, nullptr);
}
