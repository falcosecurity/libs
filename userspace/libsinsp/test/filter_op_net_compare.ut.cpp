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

#include <libsinsp/sinsp.h>
#include <gtest/gtest.h>

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, net_ipv4_compare) {
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	evt = generate_socket_events();
	int64_t return_value = 0;

	sockaddr_in client = test_utils::fill_sockaddr_in(54321, "172.40.111.222");
	sockaddr_in server = test_utils::fill_sockaddr_in(443, "142.251.111.147");

	std::vector<uint8_t> server_sockaddr =
	        test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(
	        increasing_ts(),
	        1,
	        PPME_SOCKET_CONNECT_E,
	        2,
	        sinsp_test_input::socket_params::default_fd,
	        scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	std::vector<uint8_t> socktuple =
	        test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client),
	                                   reinterpret_cast<sockaddr*>(&server));
	evt = add_event_advance_ts(
	        increasing_ts(),
	        1,
	        PPME_SOCKET_CONNECT_X,
	        4,
	        return_value,
	        scap_const_sized_buffer{socktuple.data(), socktuple.size()},
	        sinsp_test_input::socket_params::default_fd,
	        scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	EXPECT_TRUE(eval_filter(evt, "fd.ip == 142.251.111.147"));
	EXPECT_TRUE(eval_filter(evt, "fd.sip == 142.251.111.147"));
	EXPECT_TRUE(eval_filter(evt, "fd.lip == 142.251.111.147"));

	EXPECT_TRUE(eval_filter(evt, "fd.rip == 172.40.111.222"));
	EXPECT_TRUE(eval_filter(evt, "fd.cip == 172.40.111.222"));

	EXPECT_FALSE(eval_filter(evt, "fd.ip != 142.251.111.147"));

	EXPECT_TRUE(eval_filter(evt, "fd.sip != 0:0:0:0:0:0:0:1"));
	EXPECT_FALSE(eval_filter(evt, "fd.sip == '0:0:0:0:0:0:0:1'"));

	EXPECT_TRUE(eval_filter(evt, "fd.net == 142.0.0.0/4"));
	EXPECT_TRUE(eval_filter(evt, "fd.net == 142.251.0.0/8"));
	EXPECT_TRUE(eval_filter(evt, "fd.net == 142.251.111.0/16"));
	EXPECT_TRUE(eval_filter(evt, "fd.net != 10.0.0.0/8"));
	EXPECT_TRUE(eval_filter(evt, "fd.net != 2001:db8:abcd:0012::0/64"));

	EXPECT_FALSE(eval_filter(evt, "fd.net == 10.0.0.0/8"));
	EXPECT_FALSE(eval_filter(evt, "fd.net == 2001:db8:abcd:0012::0/64"));
}

TEST_F(sinsp_with_test_input, net_ipv6_compare) {
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	evt = generate_socket_events();

	int64_t return_value = 0;

	sockaddr_in6 client = test_utils::fill_sockaddr_in6(54321, "::1");
	sockaddr_in6 server1 = test_utils::fill_sockaddr_in6(443, "2001:4860:4860::8888");

	std::vector<uint8_t> server1_sockaddr =
	        test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server1));

	add_event_advance_ts(increasing_ts(),
	                     1,
	                     PPME_SOCKET_CONNECT_E,
	                     2,
	                     sinsp_test_input::socket_params::default_fd,
	                     scap_const_sized_buffer{server1_sockaddr.data(), server1_sockaddr.size()});

	std::vector<uint8_t> socktuple =
	        test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client),
	                                   reinterpret_cast<sockaddr*>(&server1));
	evt = add_event_advance_ts(
	        increasing_ts(),
	        1,
	        PPME_SOCKET_CONNECT_X,
	        4,
	        return_value,
	        scap_const_sized_buffer{socktuple.data(), socktuple.size()},
	        sinsp_test_input::socket_params::default_fd,
	        scap_const_sized_buffer{server1_sockaddr.data(), server1_sockaddr.size()});

	EXPECT_TRUE(eval_filter(evt, "fd.ip == 2001:4860:4860::8888"));
	EXPECT_TRUE(eval_filter(evt, "fd.sip == 2001:4860:4860::8888"));
	EXPECT_TRUE(eval_filter(evt, "fd.lip == 2001:4860:4860::8888"));

	EXPECT_TRUE(eval_filter(evt, "fd.rip == ::1"));
	EXPECT_TRUE(eval_filter(evt, "fd.cip == ::1"));

	EXPECT_FALSE(eval_filter(evt, "fd.ip != 2001:4860:4860::8888"));

	EXPECT_TRUE(eval_filter(evt, "fd.sip != 127.0.0.1"));
	EXPECT_FALSE(eval_filter(evt, "fd.sip == '127.0.0.1'"));

	EXPECT_TRUE(eval_filter(evt, "fd.net == 2001::0/16"));
	EXPECT_TRUE(eval_filter(evt, "fd.net == 2001:4860::0/32"));
	EXPECT_TRUE(eval_filter(evt, "fd.net == 2001:4860:4860::8888/48"));
	EXPECT_TRUE(eval_filter(evt, "fd.net != 10::0/16"));
	EXPECT_TRUE(eval_filter(evt, "fd.net != 10.0.0.0/8"));

	EXPECT_FALSE(eval_filter(evt, "fd.net == 10.0.0.0/8"));
	EXPECT_FALSE(eval_filter(evt, "fd.net == 2001:db8:abcd:0012::0/64"));
}
