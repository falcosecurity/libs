
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
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

#include <sinsp_with_test_input.h>

// Compile out this test if test_utils helpers are not defined.
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(sinsp_with_test_input, RECVMSG_success) {
	add_default_init_thread();
	open_inspector();

	// Notice: we need to generate a socket event in order to let the parser logic populate the
	// socket fdinfo. This is different from what we currently do with SEND_X event, in which case
	// the parser is able to create the fdinfo from the SEND_X event itself, even if the SOCKET_X
	// event has been dropped.
	const sinsp_test_input::socket_params sock_params = {};  // use default values.
	auto evt = generate_socket_events(sock_params);

	int64_t return_value = 55;
	uint32_t size = return_value;
	const std::string data{"hello"};
	sockaddr_in client_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
	sockaddr_in server_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SOCKET_RECVMSG_X,
	                           6,
	                           return_value,
	                           size,
	                           scap_const_sized_buffer{data.c_str(), data.size()},
	                           scap_const_sized_buffer{tuple.data(), tuple.size()},
	                           scap_const_sized_buffer{nullptr, 0},
	                           sock_params.fd);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that the size value is as expected.
	ASSERT_EQ(evt->get_param_by_name("size")->as<uint32_t>(), size);

	// Check that `get_param_value_str` returns the correct received data.
	ASSERT_EQ(evt->get_param_value_str("data"), data);

	// Check that msgcontrol is empty.
	ASSERT_EQ(evt->get_param_by_name("msgcontrol")->m_len, 0);

	// Check that fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), sock_params.fd);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	// The following information are inferred from the socket event we generated before the recvmsg
	// event.
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_TCP);
	ASSERT_TRUE(fdinfo->is_role_server());
	ASSERT_TRUE(fdinfo->is_socket_connected());

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(sock_params.fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	// The following information are inferred from the socket event we generated before the recvmsg
	// event.
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_TCP);
	ASSERT_TRUE(fdinfo->is_role_server());
	ASSERT_TRUE(fdinfo->is_socket_connected());
}
#endif
