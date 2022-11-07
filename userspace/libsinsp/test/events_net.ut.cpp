/*
Copyright (C) 2022 The Falco Authors.

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

#include "sinsp_with_test_input.h"
#include "test_utils.h"
#include <arpa/inet.h>
#include <netinet/in.h>

TEST_F(sinsp_with_test_input, ipv4_connect)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	sockaddr_in src, dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(443);
	inet_aton("142.251.111.147", &dest.sin_addr);

	src.sin_family = AF_INET;
	src.sin_port = htons(54321);
	inet_aton("172.40.111.222", &src.sin_addr);

	std::vector<uint8_t> dest_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&dest));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, PPM_AF_INET, 0x80002, 0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, 7);
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "false");

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, 7, scap_const_sized_buffer{dest_sockaddr.data(), dest_sockaddr.size()});
	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&src), reinterpret_cast<sockaddr*>(&dest));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 2, 0, scap_const_sized_buffer{socktuple.data(), socktuple.size()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "172.40.111.222:54321->142.251.111.147:443");
	ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
}

TEST_F(sinsp_with_test_input, ipv6_multiple_connects)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	sockaddr_in6 src, dest1, dest2;
	dest1.sin6_family = AF_INET6;
	dest1.sin6_port = htons(53);
	inet_pton(dest1.sin6_family, "2001:4860:4860::8888", &dest1.sin6_addr);

	dest2.sin6_family = AF_INET6;
	dest2.sin6_port = htons(2345);
	inet_pton(dest2.sin6_family, "::1", &dest2.sin6_addr);

	src.sin6_family = AF_INET6;
	src.sin6_port = htons(38255);
	inet_pton(src.sin6_family, "::1", &src.sin6_addr);

	std::vector<uint8_t> dest1_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&dest1));
	std::vector<uint8_t> dest2_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&dest2));
	scap_const_sized_buffer null_buf = scap_const_sized_buffer{nullptr, 0};

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, PPM_AF_INET6, SOCK_DGRAM, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, 3);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, 3, scap_const_sized_buffer{dest2_sockaddr.data(), dest2_sockaddr.size()});
	std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&src), reinterpret_cast<sockaddr*>(&dest2));
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 2, 0, scap_const_sized_buffer{socktuple.data(), socktuple.size()});

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, 3, scap_const_sized_buffer{dest1_sockaddr.data(), dest1_sockaddr.size()});
	// check that upon entry to the new connect the fd name is the same as during the last connection
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "::1:38255->::1:2345");

	socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&src), reinterpret_cast<sockaddr*>(&dest1));
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 2, 0, scap_const_sized_buffer{socktuple.data(), socktuple.size()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name_changed"), "true");

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SENDTO_E, 3, 3, 6, null_buf);
	// check that the socket name upon the next entry event has been properly updated
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "::1:38255->2001:4860:4860::8888:53");
}

// test a basic server connection
TEST_F(sinsp_with_test_input, bind_listen_accept_ipv4)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, PPM_AF_INET, SOCK_STREAM, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, 3);

	sockaddr_in src, dest, serv;
	serv.sin_family = AF_INET;
	serv.sin_port = htons(80);
	inet_aton("0.0.0.0", &serv.sin_addr);

	const char* local_server = "192.168.0.2";
	const char* remote_client = "192.168.0.3";

	dest.sin_family = AF_INET;
	dest.sin_port = htons(80);
	inet_aton(local_server, &dest.sin_addr);

	src.sin_family = AF_INET;
	src.sin_port = htons(40556);
	inet_aton(remote_client, &src.sin_addr);

	std::vector<uint8_t> sa = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&serv));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_E, 1, 3);

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_X, 2, 0, scap_const_sized_buffer{sa.data(), sa.size()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "0.0.0.0:80");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "true");

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_E, 2, 3, 5);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_X, 1, 0);

	std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&src), reinterpret_cast<sockaddr*>(&dest));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, 4, scap_const_sized_buffer{st.data(), st.size()}, 0, 0, 5);

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "192.168.0.3:40556->192.168.0.2:80");
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), local_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), remote_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), remote_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), local_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), "40556");
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), "80");
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), "80");
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), "40556");
	ASSERT_EQ(get_field_as_string(evt, "fd.l4proto"), "tcp");
}

// test a basic server connection with ipv6
TEST_F(sinsp_with_test_input, bind_listen_accept_ipv6)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, PPM_AF_INET6, SOCK_STREAM, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, 3);

	sockaddr_in6 src, dest, serv;
	serv.sin6_family = AF_INET6;
	serv.sin6_port = htons(80);
	inet_pton(AF_INET6, "::", &serv.sin6_addr);

	const char* local_server = "2001:db8:3333:4444:5555:6666:7777:8888";
	const char* remote_client = "2001:db8:3333:4444:5555:6666:7777:1111";

	dest.sin6_family = AF_INET6;
	dest.sin6_port = htons(80);
	inet_pton(AF_INET6, local_server, &dest.sin6_addr);

	src.sin6_family = AF_INET6;
	src.sin6_port = htons(40556);
	inet_pton(AF_INET6, remote_client, &src.sin6_addr);

	std::vector<uint8_t> sa = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&serv));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_E, 1, 3);

	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_BIND_X, 2, 0, scap_const_sized_buffer{sa.data(), sa.size()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), ":::80");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_server"), "true");

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_E, 2, 3, 5);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_LISTEN_X, 1, 0);

	std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&src), reinterpret_cast<sockaddr*>(&dest));

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, 4, scap_const_sized_buffer{st.data(), st.size()}, 0, 0, 5);

	std::string fdname = std::string(remote_client) + ":40556->" + std::string(local_server) + ":80";

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), fdname);
	ASSERT_EQ(get_field_as_string(evt, "fd.sip"), local_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.cip"), remote_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.rip"), remote_client);
	ASSERT_EQ(get_field_as_string(evt, "fd.lip"), local_server);
	ASSERT_EQ(get_field_as_string(evt, "fd.cport"), "40556");
	ASSERT_EQ(get_field_as_string(evt, "fd.sport"), "80");
	ASSERT_EQ(get_field_as_string(evt, "fd.lport"), "80");
	ASSERT_EQ(get_field_as_string(evt, "fd.rport"), "40556");
}
