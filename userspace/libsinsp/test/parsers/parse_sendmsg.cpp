
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
TEST_F(sinsp_with_test_input, SENDMSG_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	const std::string data{"hello"};
	uint32_t data_buff_size = data.size();
	int64_t fd = 25;
	sockaddr_in client_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
	sockaddr_in server_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SOCKET_SENDMSG_X,
	                                      5,
	                                      return_value,
	                                      scap_const_sized_buffer{data.c_str(), data_buff_size},
	                                      fd,
	                                      data_buff_size,
	                                      scap_const_sized_buffer{tuple.data(), tuple.size()});

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that `get_param_value_str` returns the correct sent data.
	ASSERT_EQ(evt->get_param_value_str("data"), data);

	// Check that `get_fd_info()->m_fd` returns the correct socket fd.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);

	// Check that the data size is as expected.
	ASSERT_EQ(evt->get_param_by_name("size")->as<int32_t>(), data_buff_size);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	// L4 protocol defaulted to udp.
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_UDP);
	ASSERT_TRUE(fdinfo->is_role_client());
	// In the current model, sockets are "connected" if we see traffic on it.
	ASSERT_TRUE(fdinfo->is_socket_connected());

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	// L4 protocol defaulted to udp.
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_UDP);
	ASSERT_TRUE(fdinfo->is_role_client());
	// In the current model, sockets are "connected" if we see traffic on it.
	ASSERT_TRUE(fdinfo->is_socket_connected());
}
#endif
