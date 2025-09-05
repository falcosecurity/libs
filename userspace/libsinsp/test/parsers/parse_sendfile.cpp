
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

TEST_F(sinsp_with_test_input, SENDFILE_success) {
	add_default_init_thread();
	open_inspector();

	// Notice: we need to generate socket events in order to let the parser logic populate the
	// socket fdinfos.
	constexpr int64_t in_fd = 4;
	constexpr int64_t out_fd = 5;
	sinsp_test_input::socket_params sock_params = {};  // Use default values.
	sock_params.fd = in_fd;
	auto evt = generate_socket_exit_event(sock_params);
	sock_params.fd = out_fd;
	evt = generate_socket_exit_event(sock_params);

	constexpr int64_t return_value = 55;
	constexpr uint64_t offset = 52;
	constexpr uint64_t size = 53;
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_SENDFILE_X,
	                           5,
	                           return_value,
	                           offset,
	                           out_fd,
	                           in_fd,
	                           size);

	// Check that the returned value is as expected.
	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	// Check that the offset value is as expected.
	ASSERT_EQ(evt->get_param_by_name("offset")->as<uint64_t>(), offset);
	// Check that the out_fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("out_fd")->as<int64_t>(), out_fd);
	// Check that the in_fd value is as expected.
	ASSERT_EQ(evt->get_param_by_name("in_fd")->as<int64_t>(), in_fd);
	// Check that the size value is as expected.
	ASSERT_EQ(evt->get_param_by_name("size")->as<uint64_t>(), size);

	// Check that fd info associated with the event are as expected.
	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);

	// Check that fd info associated with the thread are as expected.
	const auto init_tinfo = m_inspector.m_thread_manager->get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	fdinfo = init_tinfo->get_fd(out_fd);
	ASSERT_TRUE(fdinfo);
}
