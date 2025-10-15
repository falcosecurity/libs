
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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, SOCKETPAIR_success) {
	add_default_init_thread();
	open_inspector();

	int64_t return_value = 55;
	int64_t fd1 = 50;
	int64_t fd2 = 51;
	uint64_t source = 1234;
	uint64_t peer = 5678;
	uint32_t domain = AF_INET;
	uint32_t type = SOCK_STREAM;
	uint32_t protocol = IPPROTO_TCP;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SOCKET_SOCKETPAIR_X,
	                                      8,
	                                      return_value,
	                                      fd1,
	                                      fd2,
	                                      source,
	                                      peer,
	                                      domain,
	                                      type,
	                                      protocol);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);

	// Check that fd1 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd1")->as<int64_t>(), fd1);

	// Check that fd2 value is as expected.
	ASSERT_EQ(evt->get_param_by_name("fd2")->as<int64_t>(), fd2);

	// Check that the source value is as expected.
	ASSERT_EQ(evt->get_param_by_name("source")->as<uint64_t>(), source);

	// Check that the peer value is as expected.
	ASSERT_EQ(evt->get_param_by_name("peer")->as<uint64_t>(), peer);

	// Check that the domain value is as expected.
	ASSERT_EQ(evt->get_param_by_name("domain")->as<uint32_t>(), domain);

	// Check that the type value is as expected.
	ASSERT_EQ(evt->get_param_by_name("type")->as<uint32_t>(), type);

	// Check that the type value is as expected.
	ASSERT_EQ(evt->get_param_by_name("proto")->as<uint32_t>(), protocol);

	// Check that fd info (fd1) associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, "");
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_connected());

	const auto init_tinfo = m_inspector.m_thread_manager->find_thread(INIT_TID, true).get();
	ASSERT_TRUE(init_tinfo);

	// Checks that fdinfo associated with the thread are as expected for fd1.
	fdinfo = init_tinfo->get_fd(fd1);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, "");
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_connected());

	// Checks that fdinfo associated with the thread are as expected for fd2.
	fdinfo = init_tinfo->get_fd(fd2);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, "");
	ASSERT_TRUE(fdinfo->is_unix_socket());
	ASSERT_EQ(fdinfo->get_l4proto(), scap_l4_proto::SCAP_L4_NA);
	ASSERT_TRUE(fdinfo->is_role_none());
	ASSERT_FALSE(fdinfo->is_socket_connected());
}
