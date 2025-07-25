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
#include <test/sinsp_with_test_input.h>
#include <test/test_utils.h>

// Note:
// 1. We don't save the type of the unix socket: datagram or stream
// 2. Do we want to keep the tuple in this way `9c758d0f->9c758d0a /tmp/stream.sock`?
TEST_F(sinsp_with_test_input, CONNECT_parse_unix_socket) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_socket_events(sinsp_test_input::socket_params(PPM_AF_UNIX, SOCK_STREAM));

	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_TRUE(fdinfo->is_unix_socket());
	// todo! do we want this? In the end a unix socket could be of type datagram or stream
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_connected());
	// The socket syscall doesn't populate the name of the socket
	ASSERT_EQ(fdinfo->m_name, "");

	/* FDINFO associated with the thread */
	auto init_tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(sinsp_test_input::socket_params::default_fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_connected());
	ASSERT_EQ(fdinfo->m_name, "");

	// We don't need the enter event!
	const std::string sun_path{"/tmp/stream.sock"};
	sockaddr_un server = test_utils::fill_sockaddr_un(sun_path.c_str());
	std::vector<uint8_t> server_sockaddr =
	        test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	std::vector<uint8_t> socktuple =
	        test_utils::pack_unix_socktuple(0x9c758d0f, 0x9c758d0a, sun_path.c_str());
	evt = add_event_advance_ts(
	        increasing_ts(),
	        INIT_TID,
	        PPME_SOCKET_CONNECT_X,
	        4,
	        (int64_t)0,
	        scap_const_sized_buffer{socktuple.data(), socktuple.size()},
	        sinsp_test_input::socket_params::default_fd,
	        scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	/* FDINFO associated with the event */
	fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_client());
	ASSERT_TRUE(fdinfo->is_socket_connected());

	std::string expected_unix_tuple = "";
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	// Note: `9c758d0f` is the kernel pointer to the socket that performs the connection.
	// `9c758d0a` is the kernel pointer to the socket that receives the connection.
	// Note that the pointers are on 64 bits but the initial zeros are not rendered.
	expected_unix_tuple = "9c758d0f->9c758d0a /tmp/stream.sock";
#else
	// Also here the initial zero is not rendered.
	expected_unix_tuple = "f8d759c00000000->a8d759c00000000 /tmp/stream.sock";
#endif

	ASSERT_EQ(fdinfo->m_name, expected_unix_tuple);
	// we don't have code to populate this `m_name_raw` for sockets.
	ASSERT_EQ(fdinfo->m_name_raw, "");

	/* FDINFO associated with the thread */
	fdinfo = init_tinfo->get_fd(sinsp_test_input::socket_params::default_fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_client());
	ASSERT_TRUE(fdinfo->is_socket_connected());
	ASSERT_EQ(fdinfo->m_name, expected_unix_tuple);
	ASSERT_EQ(fdinfo->m_name_raw, "");
}

TEST_F(sinsp_with_test_input, BIND_parse_unix_socket) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 0;
	std::string unix_path = "/tmp/python_unix_udp_sockets_example";
	sockaddr_un u_sockaddr = test_utils::fill_sockaddr_un(unix_path.c_str());
	std::vector<uint8_t> server_sockaddr =
	        test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&u_sockaddr));
	uint64_t socket_fd = 77;
	auto evt = add_event_advance_ts(
	        increasing_ts(),
	        INIT_TID,
	        PPME_SOCKET_BIND_X,
	        3,
	        return_value,
	        scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()},
	        socket_fd);

	// we want to check that `get_param_value_str` returns the correct unix socket path
	ASSERT_EQ(evt->get_param_value_str("addr"), unix_path);

	// we want to check that `get_fd_info()->m_fd` returns the correct socket fd.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), socket_fd);
}
