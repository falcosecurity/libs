
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
TEST_F(sinsp_with_test_input, ACCEPT4_success) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t fd = 50;
	sockaddr_in client_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
	sockaddr_in server_sockaddr =
	        test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);
	const std::vector<uint8_t> tuple =
	        test_utils::pack_socktuple(reinterpret_cast<struct sockaddr *>(&client_sockaddr),
	                                   reinterpret_cast<struct sockaddr *>(&server_sockaddr));
	constexpr uint8_t queuepct = 4;
	constexpr uint32_t queuelen = 5;
	constexpr uint32_t queuemax = 6;
	constexpr int32_t flags = 7;

	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SOCKET_ACCEPT4_6_X,
	                                      6,
	                                      fd,
	                                      scap_const_sized_buffer{tuple.data(), tuple.size()},
	                                      queuepct,
	                                      queuelen,
	                                      queuemax,
	                                      flags);

	// Check that the fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd")->as<int64_t>(), fd);
	// Check that the queuepct value is as expected.
	ASSERT_EQ(evt->get_param_by_name("queuepct")->as<uint8_t>(), queuepct);
	// Check that the queuelen value is as expected.
	ASSERT_EQ(evt->get_param_by_name("queuelen")->as<uint32_t>(), queuelen);
	// Check that the queuemax value is as expected.
	ASSERT_EQ(evt->get_param_by_name("queuemax")->as<uint32_t>(), queuemax);
	// Check that the flags value is as expected.
	ASSERT_EQ(evt->get_param_by_name("flags")->as<int32_t>(), flags);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_TCP);
	ASSERT_TRUE(fdinfo->is_role_server());
	ASSERT_TRUE(fdinfo->is_socket_connected());

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, DEFAULT_IPV4_FDNAME);
	ASSERT_TRUE(fdinfo->is_ipv4_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_TCP);
	ASSERT_TRUE(fdinfo->is_role_server());
	ASSERT_TRUE(fdinfo->is_socket_connected());
}
#endif
